import ctypes
from pkcs11 import CK_INFO, pkcs11_command

@pkcs11_command
def library_info(pkcs11):
    pkcs11.C_GetInfo.argtypes = [ctypes.POINTER(CK_INFO)]
    pkcs11.C_GetInfo.restype = ctypes.c_ulong

    info = CK_INFO()
    rv = pkcs11.C_GetInfo(ctypes.byref(info))
    if rv != 0:
        print(f'C_GetInfo вернула ошибку: 0x{rv:08X}')
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

@pkcs11_command
def factory_reset(pkcs11, slot_id, pin, label):
    pkcs11.C_EX_InitToken.argtypes = [ctypes.c_ulong, ctypes.c_char_p, ctypes.c_char_p]
    pkcs11.C_EX_InitToken.restype = ctypes.c_ulong

    slot_id = int(slot_id)
    pin = pin.encode('utf-8')
    label = label.encode('utf-8')

    rv = pkcs11.C_EX_InitToken(slot_id, pin, label)
    if rv != 0:
        print(f'C_EX_InitToken вернула ошибку: 0x{rv:08X}')
    else:
        print('Фабричный сброс выполнен успешно.')

def list_slots():
    print('Заглушка: список слотов (не реализовано)')

def list_wallets():
    print('Заглушка: список кошельков (не реализовано)')