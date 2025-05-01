import ctypes
import sys

# Типы из PKCS#11
CK_VOID_PTR = ctypes.c_void_p

class CK_VERSION(ctypes.Structure):
    _fields_ = [
        ('major', ctypes.c_ubyte),
        ('minor', ctypes.c_ubyte),
    ]

class CK_INFO(ctypes.Structure):
    _fields_ = [
        ('cryptokiVersion',   CK_VERSION),
        ('manufacturerID',    ctypes.c_char * 32),
        ('flags',             ctypes.c_ulong),
        ('libraryDescription', ctypes.c_char * 32),
        ('libraryVersion',    CK_VERSION),
    ]

def main():
    if sys.platform.startswith('win'):
        lib_path = './rtpkcs11ecp.dll'
    else:
        lib_path = './librtpkcs11ecp.so'
    try:
        pkcs11 = ctypes.CDLL(lib_path)
    except OSError as e:
        print(f'Ошибка загрузки {lib_path}: {e}', file=sys.stderr)
        sys.exit(1)

    # Указываем сигнатуру функций
    pkcs11.C_Initialize.argtypes = [CK_VOID_PTR]
    pkcs11.C_Initialize.restype  = ctypes.c_ulong

    pkcs11.C_GetInfo.argtypes = [ctypes.POINTER(CK_INFO)]
    pkcs11.C_GetInfo.restype  = ctypes.c_ulong

    pkcs11.C_Finalize.argtypes = [CK_VOID_PTR]
    pkcs11.C_Finalize.restype  = ctypes.c_ulong

    # C_Initialize(NULL)
    rv = pkcs11.C_Initialize(None)
    if rv != 0:
        print(f'C_Initialize вернула ошибку: 0x{rv:08X}', file=sys.stderr)
        sys.exit(1)

    # C_GetInfo(&info)
    info = CK_INFO()
    rv = pkcs11.C_GetInfo(ctypes.byref(info))
    if rv != 0:
        print(f'C_GetInfo вернула ошибку: 0x{rv:08X}', file=sys.stderr)
    else:
        version = f'{info.cryptokiVersion.major}.{info.cryptokiVersion.minor}'
        libver  = f'{info.libraryVersion.major}.{info.libraryVersion.minor}'
        manuf   = info.manufacturerID.decode('utf-8', errors='ignore').strip()
        desc    = info.libraryDescription.decode('utf-8', errors='ignore').strip()
        print('Информация о PKCS#11 библиотеке:')
        print(f'  Cryptoki Version:    {version}')
        print(f'  Library Description: {desc}')
        print(f'  Manufacturer ID:     {manuf}')
        print(f'  Library Version:     {libver}')

    # C_Finalize(NULL)
    rv = pkcs11.C_Finalize(None)
    if rv != 0:
        print(f'C_Finalize вернула ошибку: 0x{rv:08X}', file=sys.stderr)

if __name__ == '__main__':
    main()
