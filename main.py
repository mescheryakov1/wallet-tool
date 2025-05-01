import argparse
import ctypes
import sys

# Перенастройка вывода для Windows
if sys.platform.startswith("win") and hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")

# Определения PKCS#11 структур
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

# Определяем функцию загрузки библиотеки по платформе

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

# Функция получения информации о библиотеке

def library_info():
    pkcs11 = load_pkcs11_lib()
    # Задаём сигнатуру функций
    pkcs11.C_Initialize.argtypes = [CK_VOID_PTR]
    pkcs11.C_Initialize.restype = ctypes.c_ulong
    pkcs11.C_GetInfo.argtypes = [ctypes.POINTER(CK_INFO)]
    pkcs11.C_GetInfo.restype = ctypes.c_ulong
    pkcs11.C_Finalize.argtypes = [CK_VOID_PTR]
    pkcs11.C_Finalize.restype = ctypes.c_ulong

    # Инициализация
    rv = pkcs11.C_Initialize(None)
    if rv != 0:
        print(f'C_Initialize вернула ошибку: 0x{rv:08X}', file=sys.stderr)
        sys.exit(1)

    info = CK_INFO()
    rv = pkcs11.C_GetInfo(ctypes.byref(info))
    if rv != 0:
        print(f'C_GetInfo вернула ошибку: 0x{rv:08X}', file=sys.stderr)
    else:
        version = f'{info.cryptokiVersion.major}.{info.cryptokiVersion.minor}'
        libver = f'{info.libraryVersion.major}.{info.libraryVersion.minor}'
        manuf = info.manufacturerID.decode('utf-8', errors='ignore').strip()
        desc = info.libraryDescription.decode('utf-8', errors='ignore').strip()
        print('Информация о PKCS#11 библиотеке:')
        print(f'  Cryptoki Version:    {version}')
        print(f'  Library Description: {desc}')
        print(f'  Manufacturer ID:     {manuf}')
        print(f'  Library Version:     {libver}')

    rv = pkcs11.C_Finalize(None)
    if rv != 0:
        print(f'C_Finalize вернула ошибку: 0x{rv:08X}', file=sys.stderr)

# Плейсхолдеры для будущего функционала

def list_slots():
    print('Заглушка: список слотов (не реализовано)')


def list_wallets():
    print('Заглушка: список кошельков (не реализовано)')

# Основная функция с разбором аргументов

def main():
    parser = argparse.ArgumentParser(
        description='Утилита для работы с PKCS#11 библиотекой Рутокен',
        formatter_class=argparse.RawTextHelpFormatter)
    parser.add_argument('--library-info', action='store_true',
                        help='Показать информацию о библиотеке (C_GetInfo)')
    parser.add_argument('--list-slots', action='store_true',
                        help='Показать список доступных слотов (заглушка)')
    parser.add_argument('--list-wallets', action='store_true',
                        help='Показать список кошельков (заглушка)')

    args = parser.parse_args()

    # Если без параметров или с --help, argparse покажет помощь
    if args.library_info:
        library_info()
    elif args.list_slots:
        list_slots()
    elif args.list_wallets:
        list_wallets()
    else:
        parser.print_help()

if __name__ == '__main__':
    main()
