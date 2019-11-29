#@keybinding alt shift e
#@menupath Emulate.Function

import sys
# the following snippet of code was copied from  
# https://github.com/dlitz/pycrypto/blob/7acba5f3a6ff10f1424c309d0d34d2b713233019/lib/Crypto/Util/py3compat.py
# https://github.com/dlitz/pycrypto/blob/7acba5f3a6ff10f1424c309d0d34d2b713233019/lib/Crypto/Util/number.py#L387
# see https://github.com/dlitz/pycrypto/blob/7acba5f3a6ff10f1424c309d0d34d2b713233019/COPYRIGHT for the original owner license terms
if sys.version_info[0] == 2:
    from types import UnicodeType as _UnicodeType   # In Python 2.1, 'unicode' is a function, not a type.

    def b(s):
        return s
    def bchr(s):
        return chr(s)
    def bstr(s):
        return str(s)
    def bord(s):
        return ord(s)
    def tobytes(s):
        if isinstance(s, _UnicodeType):
            return s.encode("latin-1")
        else:
            return ''.join(s)
    def tostr(bs):
        return unicode(bs, 'latin-1')
    # In Pyton 2.x, StringIO is a stand-alone module
    from StringIO import StringIO as BytesIO
else:
    def b(s):
       return s.encode("latin-1") # utf-8 would cause some side-effects we don't want
    def bchr(s):
        return bytes([s])
    def bstr(s):
        if isinstance(s,str):
            return bytes(s,"latin-1")
        else:
            return bytes(s)
    def bord(s):
        return s
    def tobytes(s):
        if isinstance(s,bytes):
            return s
        else:
            if isinstance(s,str):
                return s.encode("latin-1")
            else:
                return bytes(s)
    def tostr(bs):
        return bs.decode("latin-1")
    # In Pyton 3.x, StringIO is a sub-module of io
    from io import BytesIO

import struct

def long_to_bytes(n, blocksize=0):
    """long_to_bytes(n:long, blocksize:int) : string
    Convert a long integer to a byte string.
    If optional blocksize is given and greater than zero, pad the front of the
    byte string with binary zeros so that the length is a multiple of
    blocksize.
    """
    # after much testing, this algorithm was deemed to be the fastest
    s = b('')
    n = long(n)
    pack = struct.pack
    while n > 0:
        s = pack('>I', n & 0xffffffffL) + s
        n = n >> 32
    # strip off leading zeros
    for i in range(len(s)):
        if s[i] != b('\000')[0]:
            break
    else:
        # only happens when n == 0
        s = b('\000')
        i = 0
    s = s[i:]
    # add back some pad bytes.  this could be done more efficiently w.r.t. the
    # de-padding being done above, but sigh...
    if blocksize > 0 and len(s) % blocksize:
        s = (blocksize - len(s) % blocksize) * b('\000') + s
    return s

def bytes_to_long(s):
    """bytes_to_long(string) : long
    Convert a byte string to a long integer.
    This is (essentially) the inverse of long_to_bytes().
    """
    acc = 0L
    unpack = struct.unpack
    length = len(s)
    if length % 4:
        extra = (4 - length % 4)
        s = b('\000') * extra + s
        length = length + extra
    for i in range(0, length, 4):
        acc = (acc << 32) + unpack('>I', s[i:i+4])[0]
    return acc

# END OF COPIED CODE

from ghidra.program.model.address import AddressSet
from ghidra.app.emulator import EmulatorHelper
from ghidra.pcode.emulate import EmulateExecutionState
from  ghidra.app.decompiler import DecompInterface
import logging
import sys
import string
from ghidra.program.model.address import AddressSpace

logger = logging.getLogger()
logger.setLevel(logging.INFO)
handler = logging.StreamHandler(sys.stdout)
handler.setLevel(logging.INFO)
fh = logging.FileHandler('fuzz.log')
fh.setLevel(logging.INFO)
logger.addHandler(fh)
logger.addHandler(handler)
program = currentProgram

function = currentProgram.getFunctionManager().getFunctionContaining(currentAddress)

entrypoint = currentProgram.getListing().getInstructionAt(function.getEntryPoint())

decompinterface = DecompInterface()
decompinterface.openProgram(currentProgram)
result = decompinterface.decompileFunction(function, 0, monitor)

logging.info(result)
logging.info(result.getHighFunction())
highFunction = result.getHighFunction()

decompiled = str(result.getCCodeMarkup())

symbolMap = highFunction.getLocalSymbolMap()
parameterMap = {}
fuzz = 0
for parameter in [symbolMap.getParam(i) for i in range(symbolMap.getNumParams())]:
    bytesValue = askString('Setting Parameters for `{}`'.format(parameter.name), 'byte values')
    parameterMap[parameter.name] = bytesValue
    if '??' in bytesValue:
        fuzz += 1
    if '$$' in bytesValue:
        fuzz += 1
gcmd = askString('next command', 'cmd').strip()

def solveOnce(byte):

    def getAddress(offset):
        
        return currentProgram.getAddressFactory().getDefaultAddressSpace().getAddress(offset)
    def getStackAddress(offset):
        address = getAddress(emulatorHelper.readRegister
        (emulatorHelper.getStackPointerRegister()) + offset)
        orAddress = getAddress(stackPointer + offset)
        logger.debug('Stack address at {} or {}'.format(address, orAddress))
        return orAddress
    def writeStackValue(emulatorHelper, offset, size, value):
        bytesValue = long_to_bytes(value, size)
        if not emulatorHelper.getLanguage().isBigEndian():
            bytesValue = bytesValue[::-1]
        emulatorHelper.writeMemory(getStackAddress(offset), bytesValue)
    emulatorHelper = EmulatorHelper(currentProgram)

    stackPointer = (((1 << (emulatorHelper.getStackPointerRegister().getBitLength() - 1)) - 1) ^ ((1 << (emulatorHelper.getStackPointerRegister().getBitLength()//2))-1))
    returnAddressSize = currentProgram.getLanguage().getProgramCounter().getBitLength()

    NULL_PTR_RET = 0
    emulatorHelper.writeRegister(emulatorHelper.getStackPointerRegister(), stackPointer)

    logging.info('Writing %s bytes to return address', returnAddressSize)

    emulatorHelper.setBreakpoint(getStackAddress(NULL_PTR_RET))
    emulatorHelper.enableMemoryWriteTracking(True)
    logger.info('======== Test case begin {} ========'.format(byte))

    for parameter in [symbolMap.getParam(i) for i in range(symbolMap.getNumParams())]:
        bytesValue = parameterMap[parameter.name]
        bytesValue = bytesValue.replace('??', byte[0]).replace('$$', byte[1]).decode('hex')
        storage = parameter.getStorage()
        offset = 0
        parameterMap[parameter] = bytesValue
        for varnode in storage.getVarnodes():
            if varnode.getAddress().isStackAddress():
                emulatorHelper.writeMemory(getStackAddress(varnode.getAddress().getOffset()), bytesValue[offset:offset+varnode.getSize()])
            else:
                emulatorHelper.writeMemory(varnode.getAddress(), bytesValue[offset:offset+varnode.getSize()])
            offset += varnode.getSize()
            '''
            if varnode.getAddress().isStackAddress():
            # if storage.isStackStorage():
                writeStackValue(emulatorHelper, storage.getStackOffset(), parameter.getSize(), bytesValue[offset:offset+varnode.getSize()])
            elif storage.isMemoryStorage():
                raise Exception('MemoryVariable `{}` not implemented'.format(parameter))
            elif storage.isRegisterStorage():
                longValue = askLong('Setting Parameters for `{}`'.format(parameter.name), 'decimal/hex')
                emulatorHelper.writeRegister(storage.getRegister(), longValue)
            else:
                print('Unsupported parameter detected')
            '''
    from ghidra.pcode.emulate import BreakCallBack
    def nopCallBack(BreakCallBack):
        def __init__(self):
            # BreakCallBack.__init__(self)
            pass
        def pcodeCallback(self, op):
            return True
    # help(nopCallBack)
    # emulatorHelper.registerCallOtherCallback('HintPreloadData', nopCallBack(BreakCallBack()))

    printable = set(string.printable)
    def isPrintable(s):
        return sum(map(lambda x: 1 if x in printable else 0, s)) > len(s) * 3//4

    def printState():
        for symbol in program.getSymbolTable().getAllSymbols(True):
            symbolObject = symbol.getObject()
            try:
                dataType = symbolObject.getDataType()
                name = symbol.getName()
                if name in decompiled and symbol.getAddress():
                    logger.debug('Found symbol name={} type={} location={}'.format(name, dataType, symbol.getAddress()))
                    bytesValue = emulatorHelper.readMemory(symbol.getAddress(), dataType.getLength())
                    stringValue = bytesValue.tostring()
                    printValue = repr(stringValue) if isPrintable(stringValue) else stringValue.encode('hex')
                    logger.info('Variable {} has value `{}`'.format(name, printValue))
            except AttributeError as e:
                logger.debug(str(e))
                pass
            except Exception as e:
                logger.error(str(e))
            
        writeSet = emulatorHelper.getTrackedMemoryWriteSet()
        for parameter in highFunction.getLocalSymbolMap().getSymbols():
            if parameter.name not in decompiled:
                continue
            # name = parameter.name
            storage = parameter.getStorage()
            bytesValue = bytearray(0)
            for varnode in storage.getVarnodes():
                # bytesValue = askBytes('Setting Parameters for `{}`'.format(parameter.name), 'byte values')
                if varnode.getAddress().isStackAddress():
                    bytesValue.extend(emulatorHelper.readMemory(getStackAddress(varnode.getAddress().getOffset()), varnode.getSize()))
                elif writeSet.contains(varnode.getAddress()):
                    bytesValue.extend(emulatorHelper.readMemory(varnode.getAddress(), varnode.getSize()))
            stringValue = str(bytesValue)
            printValue = repr(stringValue) if isPrintable(stringValue) else stringValue.encode('hex')
            logger.info('Variable `{}` @ `{}` has value `{}`'.format(parameter.name, storage, printValue))
        
        logger.info(str(['{} = {}'.format(register, emulatorHelper.readRegister(register)) for register in currentProgram.getLanguage().getRegisters()]))

        logger.info('Stopping execution at {:x}'.format(emulatorHelper.readRegister(emulatorHelper.getPCRegister())))
        logger.debug('Logged writes at {}'.format(emulatorHelper.getTrackedMemoryWriteSet()))
        # initialize everything
    
    def readMemory(from_, size):
        bytesValue = bytearray(0)
        bytesValue.extend(emulatorHelper.readMemory(getAddress(from_), size))
        stringValue = str(bytesValue)
        logger.info('Reading from {} (size: {}): {}\n\thex={}'.format(from_, size, repr(stringValue), stringValue.encode("hex")))
    
    def updateUI():
        setCurrentSelection(AddressSet(emulatorHelper.getExecutionAddress()))
        setCurrentLocation(emulatorHelper.getExecutionAddress())
    emulatorHelper.setBreakpoint(function.getEntryPoint())
    emulatorHelper.run(function.getEntryPoint(), entrypoint, monitor)
    previousPC = None
    import time
    lcmd = gcmd
    while not monitor.isCancelled():
        if ',' in lcmd:
            cmds = lcmd.split(',')
        else:
            cmds = [lcmd[::]]
        # cmd = raw_input('> ')
        for cmd in cmds:
            cmd = cmd.split()
            if cmd[0] == 's':
                emulatorHelper.step(monitor)
            elif cmd[0] == 'c':
                emulatorHelper.run(monitor)
            elif cmd[0] == 'n':
                address = getInstructionAfter(emulatorHelper.getExecutionAddress()).getAddress()
                emulatorHelper.setBreakpoint(address)
                emulatorHelper.run(monitor)
                emulatorHelper.clearBreakpoint(address)
            elif cmd[0] == 'b':
                # address = askAddress('break point address', 'addr')
                address = getAddress(int(cmd[1], 16))
                emulatorHelper.setBreakpoint(address)
            elif cmd[0] == 'd':
                # address = askAddress('delete break point address', 'addr')
                int(cmd[1], 16)
                emulatorHelper.clearBreakpoint(address)
            elif cmd[0] == 'x':
                time.sleep(5 if len(cmd) == 1 else int(cmd[1]))
            elif cmd[0] == 'q':
                printState()
                updateUI()
                return
            elif cmd[0] == 'r':
                if len(cmd) == 3:
                    from_ = cmd[1]
                    size = int(cmd[2],16 if "0x" in cmd[2].lower() else 10)
                else:
                    from_, to_ = map(lambda x: int(x,16), cmd[1].split(":"))
                    size = to_-from_
                    from_ = hex(from_)
                readMemory(from_.replace("0x",""), size)
            elif cmd[0] == 'p':
                printState()
            else:
                print('''
        s - step
        c - continue
        n - step over/next
        d - delete bp
        b - add bp
        x - sleep for 5 seconds
        q - quit
        r - read memory addr (either `from:to` or `from size`)
        p - print state
        ''')
                continue
        printState()
        updateUI()
        lcmd = askString('next command', 'cmd').strip()
        '''
        if emulatorHelper.getEmulateExecutionState() == EmulateExecutionState.BREAKPOINT:
            break
        logger.info('Stopping execution at {:x}'.format(emulatorHelper.readRegister(emulatorHelper.getPCRegister())))
        if emulatorHelper.readRegister(emulatorHelper.getPCRegister()) == previousPC:
            emulatorHelper.writeRegister(emulatorHelper.getPCRegister(), int(previousPC + currentProgram.getListing().getCodeUnitAt(currentProgram.getAddressFactory().getDefaultAddressSpace().getAddress(previousPC)).getLength()))
            print(int(previousPC), previousPC + currentProgram.getListing().getCodeUnitAt(currentProgram.getAddressFactory().getDefaultAddressSpace().getAddress(previousPC)).getLength())
            break
            # print(emulatorHelper.getEmulateExecutionState())
        previousPC = emulatorHelper.readRegister(emulatorHelper.getPCRegister())
        emulatorHelper.run(monitor)
        '''
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

import itertools
if fuzz == 1:
    space = [('{:02x}'.format(i), '{:02x}'.format(i)) for i in range(256)]
elif fuzz == 2:
    space = itertools.product(['{:02x}'.format(i) for i in range(256)], repeat=2)
else:
    space = [('??', '??')]
for char in space:
    if monitor.isCancelled():
        break
    solveOnce(char)
