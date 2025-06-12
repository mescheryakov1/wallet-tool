import ctypes
import sys
from pkcs11_structs import CK_VOID_PTR

def load_pkcs11_lib():
    """Загружает библиотеку PKCS#11 в зависимости от платформы."""
    if sys.platform.startswith('win'):
        path = './rtpkcs11ecp.dll'
        loader = ctypes.WinDLL  # Используем stdcall для Windows
    elif sys.platform == 'darwin':
        path = './rtpkcs11ecp.dylib'
        loader = ctypes.CDLL  # Используем cdecl для macOS
    else:
        path = './librtpkcs11ecp.so'
        loader = ctypes.CDLL  # Используем cdecl для Linux

    try:
        return loader(path)
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
