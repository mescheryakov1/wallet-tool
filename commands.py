import ctypes
import sys
from pkcs11 import pkcs11_command
from pkcs11_structs import CK_INFO, CK_SLOT_INFO, CK_TOKEN_INFO, CK_ATTRIBUTE, CKA_CLASS, CKO_PUBLIC_KEY, CKF_SERIAL_SESSION, CKF_RW_SESSION
from pkcs11_definitions import define_pkcs11_functions

@pkcs11_command
def library_info(pkcs11):
    define_pkcs11_functions(pkcs11)  # Настраиваем argtypes и restype

    info = CK_INFO()
    rv = pkcs11.C_GetInfo(ctypes.byref(info))
    if rv != 0:
        print(f'C_GetInfo вернула ошибку: 0x{rv:08X}')
    else:
        version = f'{info.cryptokiVersion.major}.{info.cryptokiVersion.minor}'
        libver = f'{info.libraryVersion.major}.{info.libraryVersion.minor}'
        manuf = info.manufacturerID.decode('utf-8', errors='ignore')
        desc = info.libraryDescription.decode('utf-8', errors='ignore')
        print('Информация о PKCS#11 библиотеке:')
        print(f'  Cryptoki Version:    {version}')
        print(f'  Library Description: {desc}')
        print(f'  Manufacturer ID:     {manuf}')
        print(f'  Library Version:     {libver}')

@pkcs11_command
def factory_reset(pkcs11, slot_id, pin, label):
    define_pkcs11_functions(pkcs11)  # Настраиваем argtypes и restype

    slot_id = int(slot_id)
    pin = pin.encode('utf-8')
    label = label.encode('utf-8')

    rv = pkcs11.C_EX_InitToken(slot_id, pin, label)
    if rv != 0:
        print(f'C_EX_InitToken вернула ошибку: 0x{rv:08X}')
    else:
        print('Фабричный сброс выполнен успешно.')

@pkcs11_command
def list_slots(pkcs11):
    """Выводит список доступных слотов."""
    define_pkcs11_functions(pkcs11)  # Настраиваем argtypes и restype

    # Получаем количество слотов
    count = ctypes.c_ulong()
    rv = pkcs11.C_GetSlotList(False, None, ctypes.byref(count))
    if rv != 0:
        print(f'C_GetSlotList вернула ошибку: 0x{rv:08X}')
        return

    # Получаем список слотов
    slots = (ctypes.c_ulong * count.value)()
    rv = pkcs11.C_GetSlotList(False, slots, ctypes.byref(count))
    if rv != 0:
        print(f'C_GetSlotList вернула ошибку: 0x{rv:08X}')
        return

    print('Список доступных слотов:')
    for slot_id in slots:
        print(f'  Слот ID: {slot_id}')

@pkcs11_command
def list_wallets(pkcs11):
    """Выводит список доступных кошельков (токенов)."""
    define_pkcs11_functions(pkcs11)  # Настраиваем argtypes и restype

    # Получаем количество слотов
    count = ctypes.c_ulong()
    rv = pkcs11.C_GetSlotList(True, None, ctypes.byref(count))
    if rv != 0:
        print(f'C_GetSlotList вернула ошибку: 0x{rv:08X}')
        return

    # Получаем список слотов
    slots = (ctypes.c_ulong * count.value)()
    rv = pkcs11.C_GetSlotList(True, slots, ctypes.byref(count))
    if rv != 0:
        print(f'C_GetSlotList вернула ошибку: 0x{rv:08X}')
        return

    print('Список доступных кошельков:')
    for slot_id in slots:
        token_info = CK_TOKEN_INFO()
        rv = pkcs11.C_GetTokenInfo(slot_id, ctypes.byref(token_info))
        if rv == 0:
            label = token_info.label.decode('utf-8', errors='ignore').strip()
            manufacturer = token_info.manufacturerID.decode('utf-8', errors='ignore').strip()
            model = token_info.model.decode('utf-8', errors='ignore').strip()
            serial = token_info.serialNumber.decode('utf-8', errors='ignore').strip()
            print(f'  Кошелёк в слоте {slot_id}:')
            print(f'    Метка: {label}')
            print(f'    Производитель: {manufacturer}')
            print(f'    Модель: {model}')
            print(f'    Серийный номер: {serial}')
        else:
            print(f'  Слот {slot_id} не содержит кошелька.')

@pkcs11_command
def list_objects(pkcs11, slot_id, pin):
    """Ищет ключи в кошельке и выводит их атрибуты."""
    define_pkcs11_functions(pkcs11)  # Настраиваем argtypes и restype

    # Открываем сессию
    session = ctypes.c_ulong()
    rv = pkcs11.C_OpenSession(slot_id, CKF_SERIAL_SESSION | CKF_RW_SESSION, None, None, ctypes.byref(session))
    if rv != 0:
        print(f'C_OpenSession вернула ошибку: 0x{rv:08X}')
        return

    # Выполняем логин
    if pin:
        rv = pkcs11.C_Login(session, 1, pin.encode('utf-8'), len(pin))
        if rv != 0:
            print(f'C_Login вернула ошибку: 0x{rv:08X}')
            pkcs11.C_CloseSession(session)
            return

    # 1) создаём переменную и сохраняем её в локальной области видимости
    val = ctypes.c_ulong(CKO_PUBLIC_KEY)

    # 2) формируем структуру CK_ATTRIBUTE, приводя указатель к void*
    attr = CK_ATTRIBUTE()
    attr.type = CKA_CLASS
    attr.pValue = ctypes.cast(ctypes.pointer(val), ctypes.c_void_p)
    attr.ulValueLen = ctypes.sizeof(val)
    

    # 3) создаём массив из одного атрибута
    template = (CK_ATTRIBUTE * 1)(attr)

    # 4) инициализируем поиск
 
    rv = pkcs11.C_FindObjectsInit(session.value, template, len(template))
    if rv != 0:
        print(f'C_FindObjectsInit вернула ошибку: 0x{rv:08X}')
        pkcs11.C_CloseSession(session)
        return

    # Ищем объекты
    print('Список ключей в кошельке:')
    obj = ctypes.c_ulong()
    count = ctypes.c_ulong()
    while True:
        rv = pkcs11.C_FindObjects(session, ctypes.byref(obj), 1, ctypes.byref(count))
        if rv != 0 or count.value == 0:
            break

        # Получаем атрибуты объекта
        attributes = [
            {"type": 0x00000082, "name": "CKA_LABEL"},  # Метка
            {"type": 0x00000083, "name": "CKA_ID"},     # Идентификатор
            {"type": 0x00000086, "name": "CKA_VALUE"},  # ключа
        ]

        print(f'  ID ключа: {obj.value}')
        for attr in attributes:
            attr_template = CK_ATTRIBUTE(type=attr["type"], pValue=None, ulValueLen=0)

            # Сначала получаем размер атрибута
            rv = pkcs11.C_GetAttributeValue(session, obj, ctypes.byref(attr_template), 1)
            if rv != 0:
                print(f'    Ошибка получения {attr["name"]}: 0x{rv:08X}')
                continue

            # Если размер атрибута больше 0, получаем его значение
            if attr_template.ulValueLen > 0:
                value = (ctypes.c_ubyte * attr_template.ulValueLen)()
                attr_template.pValue = ctypes.cast(value, ctypes.c_void_p)
                rv = pkcs11.C_GetAttributeValue(session, obj, ctypes.byref(attr_template), 1)
                if rv == 0:
                    if attr["name"] == "CKA_VALUE":
                        # Ограничиваем вывод первых 64 символов
                        value_str = bytes(value).decode('utf-8', errors='ignore').replace('\x00', ' ')
                        truncated_value = value_str[:64]
                        skipped_chars = len(value_str) - 64 if len(value_str) > 64 else 0
                        print(f'    {attr["name"]}: {truncated_value} (пропущено {skipped_chars} символов)')
                    else:
                        # Проверяем, содержит ли значение непечатные символы
                        try:
                            decoded_value = bytes(value).decode('utf-8')
                            if all(32 <= ord(c) <= 126 for c in decoded_value):
                                print(f'    {attr["name"]} (TEXT): {decoded_value}')
                            else:
                                raise ValueError
                        except ValueError:
                            hex_value = " ".join(f"{b:02X}" for b in value)
                            print(f'    {attr["name"]} (HEX): {hex_value}')
                else:
                    print(f'    Ошибка получения значения {attr["name"]}: 0x{rv:08X}')

    # Завершаем поиск объектов
    pkcs11.C_FindObjectsFinal(session)

    # Закрываем сессию
    pkcs11.C_CloseSession(session)
