import ctypes
from pkcs11 import CK_INFO, pkcs11_command

class CK_SLOT_INFO(ctypes.Structure):
    _fields_ = [
        ('slotDescription', ctypes.c_char * 64),
        ('manufacturerID', ctypes.c_char * 32),
        ('flags', ctypes.c_ulong),
        ('hardwareVersion', CK_INFO),
        ('firmwareVersion', CK_INFO),
    ]

class CK_TOKEN_INFO(ctypes.Structure):
    _fields_ = [
        ('label', ctypes.c_char * 32),
        ('manufacturerID', ctypes.c_char * 32),
        ('model', ctypes.c_char * 16),
        ('serialNumber', ctypes.c_char * 16),
        ('flags', ctypes.c_ulong),
        ('ulMaxSessionCount', ctypes.c_ulong),
        ('ulSessionCount', ctypes.c_ulong),
        ('ulMaxRwSessionCount', ctypes.c_ulong),
        ('ulRwSessionCount', ctypes.c_ulong),
        ('ulMaxPinLen', ctypes.c_ulong),
        ('ulMinPinLen', ctypes.c_ulong),
        ('ulTotalPublicMemory', ctypes.c_ulong),
        ('ulFreePublicMemory', ctypes.c_ulong),
        ('ulTotalPrivateMemory', ctypes.c_ulong),
        ('ulFreePrivateMemory', ctypes.c_ulong),
        ('hardwareVersion', CK_INFO),
        ('firmwareVersion', CK_INFO),
        ('utcTime', ctypes.c_char * 16),
    ]

class CK_ATTRIBUTE(ctypes.Structure):
    _fields_ = [
        ('type', ctypes.c_ulong),
        ('pValue', ctypes.c_void_p),
        ('ulValueLen', ctypes.c_ulong),
    ]

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

@pkcs11_command
def list_slots(pkcs11):
    """Выводит список доступных слотов."""
    pkcs11.C_GetSlotList.argtypes = [ctypes.c_bool, ctypes.POINTER(ctypes.c_ulong), ctypes.POINTER(ctypes.c_ulong)]
    pkcs11.C_GetSlotList.restype = ctypes.c_ulong

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
    pkcs11.C_GetSlotList.argtypes = [ctypes.c_bool, ctypes.POINTER(ctypes.c_ulong), ctypes.POINTER(ctypes.c_ulong)]
    pkcs11.C_GetSlotList.restype = ctypes.c_ulong
    pkcs11.C_GetTokenInfo.argtypes = [ctypes.c_ulong, ctypes.POINTER(CK_TOKEN_INFO)]
    pkcs11.C_GetTokenInfo.restype = ctypes.c_ulong

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
    """Ищет сертификаты в кошельке и выводит их атрибуты."""
    # Определяем типы аргументов и возвращаемых значений для функций
    pkcs11.C_OpenSession.argtypes = [ctypes.c_ulong, ctypes.c_ulong, ctypes.c_void_p, ctypes.c_void_p, ctypes.POINTER(ctypes.c_ulong)]
    pkcs11.C_OpenSession.restype = ctypes.c_ulong
    pkcs11.C_Login.argtypes = [ctypes.c_ulong, ctypes.c_ulong, ctypes.c_char_p, ctypes.c_ulong]
    pkcs11.C_Login.restype = ctypes.c_ulong
    pkcs11.C_FindObjectsInit.argtypes = [ctypes.c_ulong, ctypes.POINTER(CK_ATTRIBUTE), ctypes.c_ulong]
    pkcs11.C_FindObjectsInit.restype = ctypes.c_ulong
    pkcs11.C_FindObjects.argtypes = [ctypes.c_ulong, ctypes.POINTER(ctypes.c_ulong), ctypes.c_ulong, ctypes.POINTER(ctypes.c_ulong)]
    pkcs11.C_FindObjects.restype = ctypes.c_ulong
    pkcs11.C_FindObjectsFinal.argtypes = [ctypes.c_ulong]
    pkcs11.C_FindObjectsFinal.restype = ctypes.c_ulong
    pkcs11.C_GetAttributeValue.argtypes = [ctypes.c_ulong, ctypes.POINTER(CK_ATTRIBUTE), ctypes.c_ulong]
    pkcs11.C_GetAttributeValue.restype = ctypes.c_ulong

    # Открываем сессию
    session = ctypes.c_ulong()
    rv = pkcs11.C_OpenSession(slot_id, 0x00000004, None, None, ctypes.byref(session))
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

    # Шаблон для поиска объектов типа "сертификат"
    CKA_CLASS = 0x00000000  # Тип объекта
    CKO_CERTIFICATE = 0x00000001  # Объект сертификата
    val = ctypes.c_ulong(CKO_CERTIFICATE)
    
    attr = CK_ATTRIBUTE()
    attr.type = CKA_CLASS
    attr.pValue = ctypes.cast(ctypes.byref(val), ctypes.c_void_p)
    attr.ulValueLen = ctypes.sizeof(val)
    
    
    template = (CK_ATTRIBUTE * 1)(attr)
    # Инициализируем поиск объектов
    rv = pkcs11.C_FindObjectsInit(session.value, ctypes.byref(template), len(template))
    if rv != 0:
        print(f'C_FindObjectsInit вернула ошибку: 0x{rv:08X}')
        pkcs11.C_CloseSession(session)
        return

    # Ищем объекты
    print('Список сертификатов в кошельке:')
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
            {"type": 0x00000086, "name": "CKA_VALUE"},  # Значение сертификата
        ]

        print(f'  Сертификат ID: {obj.value}')
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