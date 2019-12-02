import sys
sys.path.append("..")
from ghidra.program.model.address import Address
from ghidra.app.decompiler import DecompInterface
from functools import wraps
from utils import *
import struct

'''
TODO: forging NativePointer from current context (keep track of AddressSpace, Emulator etc...)
This is necessary to implement functions like malloc()
'''

DEFAULT_READ_CSTRING_SIZE = 1024

signed_format = {
    2: 'h',
    4: 'i',
    8: 'q'
}
unsigned_format = {
    2: 'H',
    4: 'I',
    8: 'Q'
}
unsigned_types = set([
'uint', 'ulong', 'ushort'
])
signed_types = set([
    'int', 'long', 'short'
])
integer_types = unsigned_types.union(signed_types)

def isPointerType(dataType):
    return 'getDataType' in dir(dataType)        

def isIntType(data_type):
    if not isinstance(data_type, str):
        data_type = data_type.getName()
    return data_type in integer_types

def unpackInt(bytes, data_type, big_endian=False):
    type_name = data_type.getName()
    if isIntType(type_name) and len(bytes) in signed_format:
        b = str(bytes)
        struct_format = ('>' if big_endian else '<') + ((signed_format if typeName in signed_types else unsigned_format)[len(b)])
        return struct.unpack(struct_format, b)[0]
    else:
        return None # failure

class NativePointer(object):
    def __init__(self, address, data_type, emulator):
        self.emulator = emulator
        self.data_type = data_type # from parameter.getDataType()
        self.pointed_type = data_type.getDataType()
        self.address = emulator.getAddress(emulator.readPointer(address))
        emulator.logger.debug('NativePointer at address %s' % str(self.address))

    # magic wrapper
    def __addressMethodWrap(self, func):
        def wrapper(*args, **kwargs):
            new_args = []
            for a in args:
                if isinstance(a, NativePointer):
                    new_args.append(a.address)
                else:
                    new_args.append(a)
            # kwargs should not be necessary cause not used
            r = func(*new_args, **kwargs)
            if isinstance(r, Address):
                return NativePointer(r, self.data_type, self.emulator)
            return r

    # be consisent with the Ghidra typing API
    def getDataType(self):
        return self.data_type
    
    def getPointedType(self):
        return self.pointed_type

    def getAddress(self):
        return self.address

    # froward fields to Address
    def __getattr__(self, name):
        r = getattr(self.address, name)
        if callable(r):
            return self.__addressMethodWrap(r)
        return r
    
    def __setattr__(self, name, val):
        return setattr(self.address, name, val)
    
    def derefRead(self):
        pointed_len = self.pointed_type.getLength()
        bid_endian = self.emulator.program.getLanguage().isBigEndian()
        self.emulator.logger.debug('reading %d bytes from %s' % (pointed_len, self.address))
        b = bytearray(0)
        b.extend(self.emulator.emulatorHelper.readMemory(self.address, pointed_len))
        if isPointerType(self.pointed_type):
            struct_format = ('>' if bid_endian else '<') + unsigned_format[pointed_len]
            address = struct.unpack(struct_format, str(b))[0]
            address = self.address.getNewAddress​(address)
            return NativePointer(address, self.pointed_type, self.emulator)
        r = unpackInt(b, self.pointed_type, bid_endian)
        if r is None:
            return str(b)
        return r
    
    def derefWrite(self, item):
        pointed_len = self.pointed_type.getLength()
        type_name = self.pointed_type.getName()
        bid_endian = self.emulator.program.getLanguage().isBigEndian()
        self.emulator.logger.debug('writing %d bytes to %s' % (pointed_len, self.address))
        if isinstance(item, bytearray):
            item = str(item)
        if isinstance(item, (long, int)):
            struct_format = ('>' if bid_endian else '<') + ((signed_format if type_name in signed_types else unsigned_format)[pointed_len])
            b = struct.pack(struct_format, item)
        elif isinstance(item, str):
            assert (len(item) == pointed_len)
            b = item
        else:
            raise ValueError("unsupported item type")
        self.emulator.emulatorHelper.writeMemory(self.address, b)

    def cast(self, data_type):
        return NativePointer(self.address, data_type, self.emulator)

    def __getitem__(self, key):
        # todo interpret the bytes recursively
        # assert(type(key) == int)
        pointed_len = self.pointed_type.getLength()
        return self.add(key * pointed_len).derefRead()
 
    def __setitem__(self, key, item):
        # assert(type(key) == int)
        pointed_len = self.pointed_type.getLength()
        self.add(key * pointed_len).derefWrite(item)

    def readCString(self, max_size=DEFAULT_READ_CSTRING_SIZE):
        ret = ""
        for i in xrange(max_size):
            r = chr(self.emulator.emulatorHelper.readMemory(self.address.add(offset + i), 1))
            ret += r
            if r == "\x00": break
        return ret

    def __repr__(self):
        return '<NativePointer(address=`%s`, pointed_type=`%s`)>' % (self.address, self.pointed_type)
    
    def __str__(self):
        return str(self.address)

