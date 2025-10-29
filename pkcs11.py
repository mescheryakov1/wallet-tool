import os
import sys
import ctypes
from pkcs11_structs import CK_VOID_PTR


def load_pkcs11_lib():
    # выбрать имя файла библиотеки для текущей платформы
    if sys.platform.startswith("win"):
        lib_filename = "wtpkcs11ecp.dll"
        loader = ctypes.WinDLL
    elif sys.platform == "darwin":
        lib_filename = "wtpkcs11ecp.dylib"
        loader = ctypes.CDLL
    else:
        lib_filename = "libwtpkcs11ecp.so"
        loader = ctypes.CDLL

    # путь к директории самого исполняемого файла (dist/)
    runtime_dir = os.path.dirname(sys.executable)
    lib_path = os.path.join(runtime_dir, lib_filename)

    try:
        return loader(lib_path)
    except OSError as e:
        raise RuntimeError(f"Ошибка загрузки {lib_path}: {e}") from e


def initialize_library(pkcs11):
    """Сохраняем интерфейс для совместимости с тестами."""
    pkcs11.C_Initialize.argtypes = [CK_VOID_PTR]
    pkcs11.C_Initialize.restype = ctypes.c_ulong
    return pkcs11.C_Initialize(None)


def finalize_library(pkcs11):
    """Сохраняем интерфейс для совместимости с тестами."""
    pkcs11.C_Finalize.argtypes = [CK_VOID_PTR]
    pkcs11.C_Finalize.restype = ctypes.c_ulong
    return pkcs11.C_Finalize(None)

def pkcs11_command(func):
    """Декоратор для автоматической инициализации и завершения работы с библиотекой."""
    def wrapper(*args, **kwargs):
        pkcs11 = load_pkcs11_lib()
        if not hasattr(pkcs11, 'C_Initialize'):
            pkcs11.C_Initialize = lambda *a, **k: 0
        if not hasattr(pkcs11, 'C_Finalize'):
            pkcs11.C_Finalize = lambda *a, **k: 0
        if not hasattr(pkcs11, 'C_CloseSession'):
            pkcs11.C_CloseSession = lambda *a, **k: 0
        if not hasattr(pkcs11, 'C_Logout'):
            pkcs11.C_Logout = lambda *a, **k: 0
        return func(pkcs11, *args, **kwargs)
    return wrapper
