import sys
sys.path.append("..")
from functools import wraps
from ghidra.app.decompiler import DecompInterface
from utils import *
function_arguments_cache = {}

class NativePointer():
    def __init__(self, address, parameter, emulator):
        self.emulator = emulator
        self.parameter = parameter
        self.pointed_type = parameter.getDataType().getDataType()
        self.address = emulator.getAddress(emulator.readPointer(address))
        emulator.logger.debug('NativePointer at address %s' % str(self.address))

    def __setitem__(self, key, item):
        # assert(type(key) == int)
        self.emulator.emulatorHelper.writeMemory(self.address.add(key * self.pointed_type.getLength()), item)
    
    def __getitem__(self, key):
        # todo interpret the bytes recursively
        # assert(type(key) == int)
        self.emulator.logger.debug('reading %d bytes from %s at %d' % (self.pointed_type.getLength(), self.address, key))
        self.emulator.logger.debug('reading %d bytes from %s at %d' % (self.pointed_type.getLength(), self.address.add(key * self.pointed_type.getLength()), key))
        ret = bytearray(0)
        ret.extend(self.emulator.emulatorHelper.readMemory(self.address.add(key * self.pointed_type.getLength()), self.pointed_type.getLength()))
        self.emulator.logger.debug('reading `%s` at %d' % (repr(ret), key))
        return str(ret)
    def __repr__(self):
        return '<NativePointer(address=`%s`, pointed_type=`%s`)>' % (self.address, self.pointed_type)

def isPointer(dataType):
    return 'getDataType' in dir(dataType)        

def isCString(dataType):
    return isPointer(dataType) and 'char' in dataType.getDataType()

def getVarnodeAddress(varnode, emulator):
    if varnode.getAddress().isStackAddress():
        return emulator.getStackAddress(varnode.getAddress().getOffset())
    else:
        return varnode.getAddress()

def getParamBytes(parameter, emulator):
    emulator.logger.debug("Found parameter `%s` with size `%d` with type `%s`" % (parameter.getName(), parameter.getSize(), str(parameter.getDataType())))
    storage = parameter.getStorage()
    content =  bytearray(0)
    for varnode in storage.getVarnodes():
        if varnode.getAddress().isStackAddress():
            content.extend(emulator.emulatorHelper.readMemory(emulator.getStackAddress(varnode.getAddress().getOffset()), varnode.getSize()))
        else:
            content.extend(emulator.emulatorHelper.readMemory(varnode.getAddress(), varnode.getSize()))
    emulator.logger.debug("got a nice content `%s`" % (repr(content)))

    return content



signed_format = {
    2: 'h',
    4: 'i',
    8: 'q'
}
unsigned_format = {
    2: 'h',
    4: 'i',
    8: 'q'
}
unsigned_types = set([
'uint', 'ulong', 'ushort'
])

signed_types = set([
    'int', 'long', 'short'
])
integer_types = unsigned_types.union(signed_types)
import struct
def getParam(parameter, emulator, monitor):
    dataType = parameter.getDataType()
    if isPointer(dataType):
        address = getVarnodeAddress(parameter.getStorage().getVarnodes()[0], emulator)
        emulator.logger.debug('parameter is at %s' % str(address))
        return NativePointer(address, parameter, emulator)
    content = getParamBytes(parameter, emulator)
    typeName = parameter.getDataType().getName()
    if typeName in integer_types and len(content) in signed_format:
        emulator.logger.debug('parameter is with type %s the content is %d bytes' % (typeName, len(content)))
        struct_format = ('>' if emulator.program.getLanguage().isBigEndian() else '<') + ((signed_format if typeName in signed_types else unsigned_format)[len(content)])
        return struct.unpack(struct_format, str(content))[0]
    return content

def args(func):
    @wraps(func)
    def wrapped(program, emulator, function, monitor):
        @wraps(func)
        def stub(address):
            functionOffset = function.getEntryPoint().getOffset()
            while functionOffset not in function_arguments_cache and not monitor.isCancelled():
                # program = currentProgram
                # function = currentProgram.getFunctionManager().getFunctionContaining(currentAddress)
                decompinterface = DecompInterface()
                decompinterface.openProgram(program)
                result = decompinterface.decompileFunction(function, 0, monitor)
                highFunction = result.getHighFunction()
                if not result.isCancelled() and not result.isTimedOut():
                    function_arguments_cache[functionOffset] = highFunction
            assert(functionOffset in function_arguments_cache)
            highFunction = function_arguments_cache[functionOffset]

            symbolMap = highFunction.getLocalSymbolMap()
            args = []
            for parameter in [symbolMap.getParam(i) for i in range(symbolMap.getNumParams())]:
                emulator.logger.debug("Found parameter `%s` with size `%d` with type `%s`" % (parameter.getName(), parameter.getSize(), str(parameter.getDataType())))
                param = getParam(parameter, emulator, monitor)
                args.append(param)
            emulator.logger.debug(str(args))
            retval = func(*args)
            emulator.logger.debug('Finish execution of hook %s with return value %s' % (func.__name__, repr(retval)))
            pointerSize = emulator.program.getLanguage().getProgramCounter().getBitLength()//8
            
            if type(retval) == int or type(retval) == long:
                retval = long_to_bytes(retval, pointerSize)
                if not emulator.program.getLanguage().isBigEndian():
                    retval = retval[::-1]
            offset = 0
            for varnode in function.getReturn().getVariableStorage().getVarnodes():
                emulator.emulatorHelper.writeMemory(varnode.getAddress(), retval[offset:offset+varnode.getSize()])
                offset += varnode.getSize()
            emulator.logger.debug('Finish execution of hook %s we were at %s before' % (func.__name__, str(emulator.lastAddresses)))
            current = emulator.emulatorHelper.getExecutionAddress()
            for address in emulator.lastAddresses:                
                emulator.logger.debug('Checking if %s is different from %s' % (address, current))
                if str(address) != str(current):
                    nextAddress = emulator.flatapi.getInstructionAfter(address).getAddress()
                    emulator.logger.debug('I propose to go to %s now' % (str(nextAddress)))
                    emulator.emulatorHelper.getEmulator().setExecuteAddress(nextAddress.getOffset())
                    emulator.logger.debug('Can you believe that we are at %s now?' % (str(emulator.emulatorHelper.getExecutionAddress())))
                    break
            return True
        emulator.logger.debug('Creating function callback for `%s`' % func.__name__)        
        return stub
    return wrapped