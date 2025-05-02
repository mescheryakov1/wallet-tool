import ctypes
import sys

CK_VOID_PTR = ctypes.c_void_p

class CK_VERSION(ctypes.Structure):
    _fields_ = [('major', ctypes.c_ubyte), ('minor', ctypes.c_ubyte)]

class CK_INFO(ctypes.Structure):
    _fields_ = [
        ('cryptokiVersion', CK_VERSION),
        ('manufacturerID', ctypes.c_char * 32),
        ('flags', ctypes.c_ulong),
        ('libraryDescription', ctypes.c_char * 32),
        ('libraryVersion', CK_VERSION),
    ]

def load_pkcs11_lib():
    if sys.platform.startswith('win'):
        path = './rtpkcs11ecp.dll'
    elif sys.platform == 'darwin':
        path = './rtpkcs11ecp.dylib'
    else:
        path = './librtpkcs11ecp.so'
    try:
        return ctypes.CDLL(path)
    except OSError as e:
        print(f'Ошибка загрузки {path}: {e}', file=sys.stderr)
        sys.exit(1)

def initialize_library(pkcs11):
    pkcs11.C_Initialize.argtypes = [CK_VOID_PTR]
    pkcs11.C_Initialize.restype = ctypes.c_ulong
    rv = pkcs11.C_Initialize(None)
    if rv != 0:
        print(f'C_Initialize вернула ошибку: 0x{rv:08X}', file=sys.stderr)
        sys.exit(1)

def finalize_library(pkcs11):
    pkcs11.C_Finalize.argtypes = [CK_VOID_PTR]
    pkcs11.C_Finalize.restype = ctypes.c_ulong
    rv = pkcs11.C_Finalize(None)
    if rv != 0:
        print(f'C_Finalize вернула ошибку: 0x{rv:08X}', file=sys.stderr)

def pkcs11_command(func):
    """Декоратор для автоматической инициализации и завершения работы с библиотекой."""
    def wrapper(*args, **kwargs):
        pkcs11 = load_pkcs11_lib()
        initialize_library(pkcs11)
        try:
            return func(pkcs11, *args, **kwargs)
        finally:
            finalize_library(pkcs11)
    return wrapper