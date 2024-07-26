# TODO: fix imported names?

import argparse
import pefile as pef
import numpy as np
import struct

thunkDict = {}
thunks = []
thunkName = {}
verbose = False
nearCallCount = 0
nearJmpCount = 0

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('file', type=str, nargs=1,
                        help="path to the PE file you want to fix")
    parser.add_argument('out', type=str, help='PE file to output to')
    parser.add_argument('-v', '--verbose', help='verbose logging', action='store_true')
    
    args = parser.parse_args()
    
    global verbose
    verbose = args.verbose
    
    print('-- dump fixer')
    print(f'[?] Fixing imports of {args.file[0]}')

    with open(args.file[0], 'rb') as f:
        fbuf = f.read()
    buf = bytearray(fbuf)
    
    pefile = pef.PE(args.file[0])

    base = pefile.OPTIONAL_HEADER.ImageBase

    pefile.parse_data_directories()
    for entry in pefile.DIRECTORY_ENTRY_IMPORT:
        dlog(entry.dll)
        for imp in entry.imports:
            thunk = struct.unpack('<Q', buf[imp.address-base:imp.address-base+8])[0]
            dlog(f'\t{imp.name} @ {hex(imp.address)} [{hex(thunk)}]')
            thunkDict.update({thunk: imp.address})
            thunkName.update({thunk: imp.name})

    print(f'[?] Patching import near calls... ')
    scan_nearcall(buf, base) # could probably bring this down to one scan but it's still quite fast so im not worried
    
    print('[?] Patching import near jmps... ')
    scan_nearjmp(buf, base)
    print(f'[?] Patched {nearCallCount} near calls, and {nearJmpCount} near jmps.')
    
    
    
    print(f'[?] Writing patched binary to {args.out}')
    with open(args.out, 'wb') as f:
        f.write(buf)

def dlog(msg):
    if verbose == True:
        print(msg)

def get_import_address(thunk):
    return thunkDict.get(thunk)

def correct_nearcall(buf, offset, base):
    relAddr = np.frombuffer(buf[offset+2:offset+6], dtype=np.int32)[0]
    
    callAddr = relAddr.item() + base + offset + 6 

    if relAddr > len(buf) - 2 - offset + 6 or callAddr < base:
        importAddr = thunkDict.get(callAddr)
        if importAddr == None:
            return
        
        relImportAddr = -((base + offset + 6) - importAddr) - 1
        
        dlog(f'[?] Patching near call at {hex(base+offset)} to {hex(relImportAddr)} [{hex(thunkDict.get(callAddr))}, {thunkName.get(callAddr)}]')
        packedImportAddr = struct.pack('<i', relImportAddr)
        patch = b'\x48\xff\x15' + packedImportAddr + b'\x0f\x1f\x44\x00\x00' # call packedImportAddress, then multibyte nop
        buf[offset:offset + len(patch)] = patch
        global nearCallCount
        nearCallCount += 1
        return
    
def correct_nearjmp(buf, offset, base):
    relAddr = np.frombuffer(buf[offset+2:offset+6], dtype=np.int32)[0]
    jmpAddr = relAddr.item() + base + offset + 6
    if relAddr > len(buf) - 2 - offset + 6 or jmpAddr < base:
        importAddr = thunkDict.get(jmpAddr)
        if importAddr == None:
            return
        
        relImportAddr = -((base + offset + 6) - importAddr)
        dlog(f'[?] Patching near jmp at {hex(base+offset)} to {hex(relImportAddr)} [{hex(thunkDict.get(jmpAddr))}, {thunkName.get(jmpAddr)}]')
        packedImportAddr = struct.pack('<i', relImportAddr)
        patch = b'\xff\x25' + packedImportAddr # jmp qword ptr packedImportAddr
        buf[offset:offset + len(patch)] = patch
        global nearJmpCount
        nearJmpCount += 1
        return

def scan_nearcall(buf, base):
    sig1=bytearray(b'\x48\xe8')             # call    near ptr ? ? ? ?
    sig2=bytearray(b'\x66\x0f\x1f\x44\x00') # nop     word ptr [rax+rax+00h]
    for i in range(len(buf)-len(sig2)+1):
        scanbytes1 = bytearray(buf[i:i+len(sig1)])
        scanbytes2 = bytearray(buf[i+6:i+6+len(sig2)])
        
        if scanbytes1 == sig1 and scanbytes2 == sig2:
            correct_nearcall(buf, i, base)
            
def scan_nearjmp(buf, base):
    sig = bytearray(b'\x48\xe9') # jmp near ptr ? ? ? ?
    for i in range(len(buf)-len(sig)+1):
        scanbytes = bytearray(buf[i:i+len(sig)])
        if scanbytes == sig:
            correct_nearjmp(buf, i, base)

if __name__ == '__main__':
    main()