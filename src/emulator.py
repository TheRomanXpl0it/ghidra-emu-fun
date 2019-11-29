#@description This is not the emulator file script, run emulate_function.py
from ghidra.program.model.address import AddressSpace
from ghidra.app.emulator import EmulatorHelper
from ghidra.app.decompiler import DecompInterface
from ghidra.program.flatapi import FlatProgramAPI
from ghidra.pcode.emulate import EmulateExecutionState, BreakCallBack
import logging
import sys
import string
import time
import random
from functools import wraps
import lib
import struct

from utils import *

class EmulatorState:
    WAITING_FOR_PARAM, READY, EXECUTING, DONE = range(4)
def history(func):
    @wraps(func)
    def wrapper(*args):
        args[0].logger.debug(args[1])
        args[0].history.append(' '.join(args[1]))
        func(*args)
    return wrapper

class DucktapeBreakCallback(BreakCallBack):
    def __init__(self, addressCallback, pcodeCallback):
        self.address_callback = addressCallback
        self.pcode_callback = pcodeCallback
    def addressCallback(self, address):
        self.address_callback(address)
        return True

class Emulator(object):
    def __init__(self, plugin, state=None, logger_fname="ghidra_emulator.txt"):
        self.plugin = plugin
        self.monitor = self.plugin.getMonitor()
        if state is None:
            state = self.plugin.getGhidraState()
        program = state.getCurrentProgram()
        address = state.getCurrentAddress()

        self.byte_substitution = {}

        self.initLogger(logger_fname)
        self.initEmulator(program, address)
        self.initCmdHandlers()

        self.emulator_state = EmulatorState.WAITING_FOR_PARAM
        self.flatapi = FlatProgramAPI(program)

    def initLogger(self, fname):
        self.logger_fname = fname
        
        self.logger = logging.getLogger(str(random.random()).replace(".","_"))
        self.logger.setLevel(logging.INFO)
        
        h_stdout = logging.StreamHandler(sys.stdout)
        h_stdout.setLevel(logging.INFO)
        self.logger.addHandler(h_stdout)
        if self.logger_fname:
            h_file = logging.FileHandler(self.logger_fname)
            h_file.setLevel(logging.INFO)
            self.logger.addHandler(h_file)

    def initEmulator(self, program, address, clear_param_map=True):
        ''' Setup the emulator helper, symbol maps and fn related stuff '''
        self.program = program
        self.function = self.program.getFunctionManager().getFunctionContaining(address)
        if self.function is None:
            function_name = self.plugin.askString("You are not in a function, please enter an address or a function name", "address or symbol name")
            for f in self.plugin.state.currentProgram.getFunctionManager().getFunctions(True):
                if function == f.getName():
                    self.plugin.state.setCurrentAddress(function.getEntryPoint())
                    self.doStart()
                    return
            for f in self.plugin.state.currentProgram.getFunctionManager().getFunctions(True):
                if int(function, 16) == f.getEntryPoint().getOffset():
                    self.plugin.state.setCurrentAddress(function.getEntryPoint())
                    self.doStart()
                    return
        self.entrypoint = self.program.getListing().getInstructionAt(self.function.getEntryPoint())

        self.logger.info("Program: %s" % self.program)
        self.logger.info("Function: %s" % self.function)

        self.decompinterface = DecompInterface()
        self.decompinterface.openProgram(program)
        result = self.decompinterface.decompileFunction(self.function, 0, self.monitor)
        self.highFunction = result.getHighFunction()
        # self.logger.info(result)
        # self.logger.info(self.highFunction)

        self.decompiled = str(result.getCCodeMarkup())
        # self.logger.info("Decompiled: %s" % self.decompiled)

        self.symbolMap = self.highFunction.getLocalSymbolMap()
        # self.logger.info(self.symbolMap)
        if clear_param_map:
            self.parameterMap = {}
        # fuzz = 0

        self.emulatorHelper = EmulatorHelper(self.program)
        self.stackPointer = (((1 << (self.emulatorHelper.getStackPointerRegister().getBitLength() - 1)) - 1) ^ ((1 << (self.emulatorHelper.getStackPointerRegister().getBitLength()//2))-1))    
        self.returnAddressSize = program.getLanguage().getProgramCounter().getBitLength()

        NULL_PTR_RET = 0
        self.emulatorHelper.writeRegister(self.emulatorHelper.getStackPointerRegister(), self.stackPointer)
        self.emulatorHelper.setBreakpoint(self.getStackAddress(NULL_PTR_RET))
        self.emulatorHelper.enableMemoryWriteTracking(True)

        self.emulator_state = EmulatorState.WAITING_FOR_PARAM
        if not clear_param_map:
            self.emulator_state = EmulatorState.READY
        self.history = []        

        self.lastAddresses = []
        # self.emulatorHelper.getEmulator().executeInstruction = executeInstruction

        self.hookExternalFunctions()
        # def nopCallBack(BreakCallBack):
        #     def __init__(self):
        #         # BreakCallBack.__init__(self)
        #         pass
        #     def pcodeCallback(self, op):
        #         return True
        # help(nopCallBack)
        # emulatorHelper.registerCallOtherCallback('HintPreloadData', nopCallBack(BreakCallBack()))

    def hookExternalFunctions(self):
        for externalFunction in list(self.program.getFunctionManager().getExternalFunctions()):
            self.logger.debug('Found external function `%s`' % (externalFunction.getName()))
            for library in lib.exports:
                self.logger.debug('Found library `%s`' % (library.name))
                for function in library.exports:
                    self.logger.debug('Found function `%s`' % (function.__name__))
                    if externalFunction.getName() == function.__name__:
                        for address in externalFunction.getFunctionThunkAddresses():
                            self.logger.info('Hooked function `%s`@%s with implementation lib/%s/%s' % (externalFunction.getName(), str(address), library.name, function.__name__))
                            callback = DucktapeBreakCallback(function(self.program, self, self.program.getFunctionManager().getFunctionAt(address), self.monitor), lambda x: True)
                            # callback.addressCallback = function(self.program, self, self.program.getFunctionManager().getFunctionAt(address), self.monitor)
                            self.emulatorHelper.emulator.getBreakTable().registerAddressCallback(address, callback)
                            # self.emulatorHelper.setBreakpoint(address)
                        # break
        for thunkFunction in list(filter(lambda x: x.isThunk(), self.program.getFunctionManager().getFunctions(True))):
            for library in lib.exports:
                self.logger.debug('Found library `%s`' % (library.name))
                for function in library.exports:
                    self.logger.debug('Found function `%s`' % (function.__name__))
                    if thunkFunction.getName() == function.__name__:
                        address = thunkFunction.getEntryPoint() 
                        self.logger.info('Hooked function `%s` at %s with implementation lib/%s/%s' % (thunkFunction.getName(), str(address), library.name, function.__name__))
                        callback = DucktapeBreakCallback(function(self.program, self, self.program.getFunctionManager().getFunctionAt(address), self.monitor), lambda x: True)
                        # callback.addressCallback = function(self.program, self, self.program.getFunctionManager().getFunctionAt(address), self.monitor)
                        self.emulatorHelper.emulator.getBreakTable().registerAddressCallback(address, callback)
                            
        
    def initFunctionParameters(self, bytesValueBuffer=""):
        ''' Setup fn input parameters '''
        self.input_wildcards = []
        self.fnParametersAllBytesValue = ""
        for parameter in [self.symbolMap.getParam(i) for i in range(self.symbolMap.getNumParams())]:
            psize = self.parameterStorageSize(parameter)
            if len(bytesValueBuffer) < psize*2:
                bytesValueBuffer = self.plugin.askString('Setting Parameters for `{}` (size: {})'.format(parameter.name, psize), 'byte values')
            bytesValue = bytesValueBuffer[:psize*2]
            bytesValue = (bytesValue + "00"*psize)[:psize*2]
            assert(len(bytesValue) == psize*2)

            for i in range(0,len(bytesValue), 2):
                if bytesValue[i] in string.hexdigits and bytesValue[i+1] in string.hexdigits: continue
                self.input_wildcards.append(bytesValue[i:i+2])
            
            self.parameterMap[parameter.name] = bytesValue
            self.fnParametersAllBytesValue += bytesValue
            
            bytesValueBuffer = bytesValueBuffer[psize*2:]
        # self.logger.info(self.parameterMap)
        if self.input_wildcards:
            self.logger.info("Found %d wildcards: %s" % (len(self.input_wildcards), self.input_wildcards))
            self.logger.info("The next batch of cmds will be executed in fuzzing mode")
        
        for w in self.input_wildcards:
            self.byte_substitution[w] = "00"
        
        self.emulator_state = EmulatorState.READY

    # @staticmethod
    def parameterStorageSize(self, parameter):
        return sum(map(lambda x: x.getSize(), parameter.getStorage().getVarnodes()))

    def getAddress(self, offset):
        return self.program.getAddressFactory().getDefaultAddressSpace().getAddress(offset)

    def getStackAddress(self, offset):
        address = self.getAddress(self.emulatorHelper.readRegister(self.emulatorHelper.getStackPointerRegister()) + offset)
        orAddress = self.getAddress(self.stackPointer + offset)
        self.logger.debug('Stack address at {} or {}'.format(address, orAddress))
        return orAddress

    def writeStackValue(offset, size, value):
        bytesValue = long_to_bytes(value, size)
        if not self.emulatorHelper.getLanguage().isBigEndian():
            bytesValue = bytesValue[::-1]
        self.emulatorHelper.writeMemory(self.getStackAddress(offset), bytesValue)

    def applyByteSubstitution(self, bytesValue):
        for k,v in self.byte_substitution.items():
            bytesValue = bytesValue.replace(k, v)
        return bytesValue.decode('hex')

    def start(self, byte_substitution=None):
        ''' Write the fn inputs in memory (eventually applying the byte substitution) and 
            start the emulation, breaking at fn entry point'''
        assert(self.emulator_state == EmulatorState.READY)
        if byte_substitution is not None:
            self.byte_substitution = byte_substitution

        self.logger.info('Started with byte_sub: %r' % self.byte_substitution)
        
        for parameter in [self.symbolMap.getParam(i) for i in range(self.symbolMap.getNumParams())]:
            bytesValue = self.parameterMap[parameter.name]
            bytesValue = self.applyByteSubstitution(bytesValue)
            storage = parameter.getStorage()
            offset = 0
            for varnode in storage.getVarnodes():
                chunk = bytesValue[offset:offset+varnode.getSize()]
                if varnode.getAddress().isStackAddress():
                    self.emulatorHelper.writeMemory(self.getStackAddress(varnode.getAddress().getOffset()), chunk)
                else:
                    self.emulatorHelper.writeMemory(varnode.getAddress(), chunk)
                offset += varnode.getSize()

        self.emulatorHelper.setBreakpoint(self.function.getEntryPoint())
        self.emulatorHelper.run(self.function.getEntryPoint(), self.entrypoint, self.monitor)

        self.emulator_state = EmulatorState.EXECUTING

    def executeCmds(self, cmds):
        assert(self.emulator_state == EmulatorState.EXECUTING)
        cmds = cmds.strip().split(', ')
        for cmd_id, cmd in enumerate(cmds):
            cmd = cmd.strip().split()
            if cmd[0] not in self.cmd_handlers:
                self.logger.error("Unknown command %s (%r)" % (cmd[0], cmd))
                self.cmdHelp(cmd)
                break

            res = self.cmd_handlers[cmd[0]](cmd)
            if res: self.last_result = res
            self.updateUI()
        # self.printState()
        self.logger.info('Stopping execution for {} at {:x} with error {}'.format(self.emulatorHelper.getEmulateExecutionState(), self.emulatorHelper.readRegister(self.emulatorHelper.getPCRegister()), self.emulatorHelper.getLastError()))
    
    def printState(self):
        for symbol in self.program.getSymbolTable().getAllSymbols(True):
            symbolObject = symbol.getObject()
            try:
                dataType = symbolObject.getDataType()
                name = symbol.getName()
                if name in self.decompiled and symbol.getAddress():
                    self.logger.debug('Found symbol name={} type={} location={}'.format(name, dataType, symbol.getAddress()))
                    bytesValue = self.emulatorHelper.readMemory(symbol.getAddress(), dataType.getLength())
                    stringValue = bytesValue.tostring()
                    printValue = repr(stringValue) if isPrintable(stringValue) else stringValue.encode('hex')
                    self.logger.info('Variable {} has value `{}`'.format(name, printValue))
            except AttributeError as e:
                self.logger.debug(str(e))
            except Exception as e:
                self.logger.error(str(e))
        
        writeSet = self.emulatorHelper.getTrackedMemoryWriteSet()
        for parameter in self.highFunction.getLocalSymbolMap().getSymbols():
            if parameter.name not in self.decompiled:
                continue
            storage = parameter.getStorage()
            bytesValue = bytearray(0)
            for varnode in storage.getVarnodes():
                if varnode.getAddress().isStackAddress():
                    bytesValue.extend(self.emulatorHelper.readMemory(self.getStackAddress(varnode.getAddress().getOffset()), varnode.getSize()))
                elif writeSet.contains(varnode.getAddress()):
                    bytesValue.extend(self.emulatorHelper.readMemory(varnode.getAddress(), varnode.getSize()))
            stringValue = str(bytesValue)
            printValue = repr(stringValue) if isPrintable(stringValue) else stringValue.encode('hex')
            self.logger.info('Variable `{}` @ `{}` has value `{}`'.format(parameter.name, storage, printValue))
        
        for register in self.emulatorHelper.getLanguage().getRegisters():
            if register.isBaseRegister() and not register.isProcessorContext():
                self.logger.debug(str(register))
                self.logger.debug(str(self.emulatorHelper.readRegister(register)))

        self.logger.debug(str(self.emulatorHelper))
        self.logger.debug(str(self.emulatorHelper.getLanguage()))
        self.logger.debug(str(self.emulatorHelper.getLanguage().getRegisters()))
        self.logger.info(str(['{} = {}'.format(register, self.emulatorHelper.readRegister(register)) for register in self.emulatorHelper.getLanguage().getRegisters() if register.isBaseRegister() and not register.isProcessorContext()]))

        self.logger.info('Stopping execution at {:x}'.format(self.emulatorHelper.readRegister(self.emulatorHelper.getPCRegister())))
        self.logger.debug('Logged writes at {}'.format(self.emulatorHelper.getTrackedMemoryWriteSet()))
    
    def readMemory(self, from_, size):
        bytesValue = bytearray(0)
        bytesValue.extend(self.emulatorHelper.readMemory(self.getAddress(from_), size))
        stringValue = str(bytesValue)
        self.logger.info('Reading from {} (size: {}): {}\n\thex={}'.format(from_, size, repr(stringValue), stringValue.encode("hex")))
        return stringValue


    def readPointer(self, address):
        self.logger.debug('reading %d from address %s' % (self.program.getLanguage().getProgramCounter().getBitLength()//8, str(address)))
        packed = bytearray(0)
        packed.extend(self.emulatorHelper.readMemory(address, self.program.getLanguage().getProgramCounter().getBitLength()//8))
        self.logger.debug('reading `%s` from address' % repr(str(packed)))
        if not self.program.getLanguage().isBigEndian():
            packed = str(packed[::-1])
        self.logger.debug('got pointer at `%s`' % repr(str(packed)))        
        return int(packed.encode('hex'), 16)
    def writeMemory(self, from_, bytesValue):
        bytesValue = self.applyByteSubstitution(bytesValue)
        self.emulatorHelper.writeMemory(self.getAddress(from_), bytesValue)
    
    def updateUI(self):
        self.plugin.syncView(self.emulatorHelper.getExecutionAddress())

    def initCmdHandlers(self):
        self.cmd_handlers = {
            's': self.cmdStep,
            'c': self.cmdContinue,
            'n': self.cmdNext,
            'b': self.cmdBreakpointAdd,
            'd': self.cmdBreakpointRemove,
            'x': self.cmdSleep,
            'q': self.cmdQuit,
            'r': self.cmdReadMem,
            'w': self.cmdWriteMem,
            'p': self.cmdPrintState,
            'h': self.cmdHelp,
            'l': self.cmdLogHistory,
            'e': self.cmdEval,
            'hook': self.cmdHook,
            'list-hooks': self.cmdListHook,
        }

    
    @history
    def cmdHook(self, cmd):
        '''hook address module.function - replace a function with a python implementation
        e.g. hook 0x40000 libc6.puts
        '''
        address = self.getAddress(int(cmd[1], 16))
        library_name, function_name = cmd[2].split('.')
        thunkedFunction = self.program.getFunctionManager().getFunctionContaining(address)
        for library in lib.exports:
            if library_name == library_name:
                self.logger.debug('Found library `%s`' % (library.name))
                for function in library.exports:
                    self.logger.debug('Found function `%s`' % (function.__name__))
                    if function_name == function.__name__:
                        self.logger.info('Hooked function `%s` at %s with implementation lib/%s/%s' % (thunkedFunction.getName(), str(address), library.name, function.__name__))
                        callback = DucktapeBreakCallback(function(self.program, self, thunkedFunction, self.monitor), lambda x: True)
                        # callback.addressCallback = function(self.program, self, self.program.getFunctionManager().getFunctionAt(address), self.monitor)
                        self.emulatorHelper.emulator.getBreakTable().registerAddressCallback(address, callback)
                        break
    @history
    def cmdListHook(self, cmd):
        '''List available hooks
        '''
        for library in lib.exports:
            self.logger.debug('Found library `%s`' % (library.name))
            for function in library.exports:
                self.logger.debug('Found function `%s`' % (function.__name__))
                self.logger.info('%s.%s - %s' % (library.name, function.__name__, function.__doc__))

    @history
    def cmdStep(self, cmd):
        '''step'''
        self.emulatorHelper.step(self.monitor)
    def run(self, monitor):
        self.emulatorHelper.emulator.setHalt(False)
        while not self.emulatorHelper.emulator.getHalt():
            self.emulatorHelper.step(monitor)
            currentAddress = self.emulatorHelper.getExecutionAddress()
            if len(self.lastAddresses) == 0 or self.lastAddresses[0] != currentAddress:
                self.lastAddresses = [currentAddress] + self.lastAddresses[:1]

    @history
    def cmdContinue(self, cmd):
        '''continue'''
        self.run(self.monitor)
    
    @history
    def cmdNext(self, cmd):
        '''step over/next'''
        address = self.flatapi.getInstructionAfter(self.emulatorHelper.getExecutionAddress()).getAddress()
        self.emulatorHelper.setBreakpoint(address)
        self.run(self.monitor)
        self.emulatorHelper.clearBreakpoint(address)
        
    @history
    def cmdBreakpointAdd(self, cmd):
        '''add breakpoint (`hex_address`)'''
        address = self.getAddress(int(cmd[1], 16))
        self.emulatorHelper.setBreakpoint(address)

    @history
    def cmdBreakpointRemove(self, cmd):
        '''remove breakpoint (`hex_address`)'''
        address = self.getAddress(int(cmd[1], 16))
        self.emulatorHelper.clearBreakpoint(address)

    @history
    def cmdSleep(self, cmd):
        '''sleep (`time(=5)`)'''
        for i in range(10000):
            self.monitor.isCancelled()
        # time.sleep(5 if len(cmd) == 1 else int(cmd[1]))
    
    @history
    def cmdQuit(self, cmd):
        '''quit'''
        self.printState()
        self.updateUI()
        self.emulator_state = EmulatorState.DONE

    @history
    def cmdReadMem(self, cmd):
        '''read memory addr (either `hex_from:hex_to` or `hex_from size`)'''
        if len(cmd) == 3:
            from_ = cmd[1]
            size = int(cmd[2], 16 if "0x" in cmd[2].lower() else 10)
        else:
            from_, to_ = map(lambda x: int(x,16), cmd[1].split(":"))
            size = to_-from_
            from_ = hex(from_)
        return self.readMemory(from_.replace("0x",""), size)
    
    @history
    def cmdWriteMem(self, cmd):
        '''write memory addr (`hex_addr hex_bytes`)'''
        self.writeMemory(cmd[1], cmd[2])
    
    @history
    def cmdPrintState(self, cmd):
        '''print state'''
        self.printState()

    @history
    def cmdEval(self, cmd):
        '''executes your command'''
        exec(' '.join(cmd[1:]))

    def cmdHelp(self, cmd):
        '''help'''
        self.logger.info("Commands:")
        for k,v in self.cmd_handlers.items():
            self.logger.info("\t%s: %s" % (k, v.__doc__))

    def cmdLogHistory(self, cmd):
        '''prints a serialized version of this debugging session'''
        self.logger.debug(self.history)
        self.logger.info("`%s`" % (', '.join(self.history)))


_printable = set(string.printable)
def isPrintable(s):
    return sum(map(lambda x: 1 if x in _printable else 0, s)) > len(s) * 3//4

"""
gcmd = ""
def solveOnce(byte, CMDS=None):    
    global gcmd
    returnValue = function.getReturn()
    value = '<not found>'
    if returnValue.isStackVariable():
        value = emulatorHelper.readStackValue(returnValue.getStackOffset(), returnValue.getLength())
    elif returnValue.isMemoryVariable():
        raise Exception('MemoryVariable `{}` not implemented'.format(returnValue))
    elif returnValue.isRegisterVariable():
        value = emulatorHelper.readRegister(returnValue.getRegister())
    else:
        print('Unsupported returnValue detected')
    logger.info('Found value `{}` for `{}`'.format(value, returnValue.name))
    logger.info('======== Test case finish {} ========'.format(byte))

# BF the right way
# for i in range(256):
#     if solveOnce(('??','??'), CMDS="b 17b0, b 189c, c, w 0x7ffeffa4 {}, r 0x7ffeffa4 4, c, r 0x7ffeff80 32, ret".format(chr(i).encode("hex"))) == "703224f765d313ee4ed0fadcf9d63a5e":
#         print "Solved:",i
#         break
# exit(1)
