import ctypes
import sys
from pkcs11 import pkcs11_command
from pkcs11_structs import (
    CK_INFO,
    CK_TOKEN_INFO,
    CK_TOKEN_INFO_EXTENDED,
    CK_ATTRIBUTE,
    CKA_CLASS,
    CKA_LABEL,
    CKA_ID,
    CKA_KEY_TYPE,
    CKA_VALUE,
    CKO_PUBLIC_KEY,
    CKO_PRIVATE_KEY,
    CKF_SERIAL_SESSION,
    CKF_RW_SESSION,
    CKR_TOKEN_NOT_PRESENT,
    CKK_RSA,
    CKK_EC,
    CKK_EC_EDWARDS,
    CKK_EC_MONTGOMERY,
    CKK_GOSTR3410,
    CKA_TOKEN,
    CKA_PRIVATE,
    CKA_MODULUS_BITS,
    CKA_PUBLIC_EXPONENT,
    CKA_EC_PARAMS,
    CKA_GOSTR3410_PARAMS,
    CKA_GOSTR3411_PARAMS,
    CKM_RSA_PKCS_KEY_PAIR_GEN,
    CKM_EC_KEY_PAIR_GEN,
    CKM_EC_EDWARDS_KEY_PAIR_GEN,
    CKM_GOSTR3410_KEY_PAIR_GEN,
    CK_MECHANISM,
    CKU_USER,
    TOKEN_FLAGS_USER_PIN_NOT_DEFAULT,
    TOKEN_FLAGS_SUPPORT_JOURNAL,
    TOKEN_FLAGS_USER_PIN_UTF8,
    TOKEN_FLAGS_FW_CHECKSUM_UNAVAILIBLE,
    TOKEN_FLAGS_FW_CHECKSUM_INVALID,
)
from pkcs11_definitions import define_pkcs11_functions

key_type_description = {
    CKK_RSA: "RSA",
    CKK_EC: "ECDSA (bitcoin, ethereum, tron и т.д.)",
    CKK_EC_EDWARDS: "EdDSA (solana, ton и т.д.)",
    CKK_EC_MONTGOMERY: "EdDSA (solana, ton и т.д.)",
    CKK_GOSTR3410: "ГОСТ 34.10-2012",
}


def format_attribute_value(value: bytes, mode: str) -> str:
    """Return string representation of attribute value.

    Parameters
    ----------
    value: bytes
        Raw value returned from PKCS#11.
    mode: str
        Either ``"hex"`` or ``"text"``.

    Returns
    -------
    str
        String suitable for console output. If value cannot be represented in
        requested mode, ``"двоичные данные"`` is returned.
    """

    if mode == "hex":
        hex_part = " ".join(f"{b:02X}" for b in value[:30])
        if len(value) > 30:
            hex_part += " ..."
        return hex_part

    if mode == "text":
        try:
            decoded = value.decode("utf-8")
        except UnicodeDecodeError:
            return "двоичные данные"
        if not all(ch.isprintable() or ch.isspace() for ch in decoded):
            return "двоичные данные"
        if len(decoded) > 30:
            return decoded[:30] + "..."
        return decoded

    raise ValueError(f"Unknown mode {mode}")


def _decode_char_array(char_array) -> str:
    raw = bytes(char_array)
    text = raw.rstrip(b"\0 ").decode("utf-8", errors="ignore").strip()
    return text if text else "—"


def _format_version(version) -> str:
    return f"{version.major}.{version.minor}"


def _format_hex_bytes(data: bytes) -> str:
    if not data:
        return "—"
    return " ".join(f"{byte:02X}" for byte in data)


def _prepare_value(value) -> str:
    if value is None:
        return "—"
    if isinstance(value, str):
        return value if value else "—"
    return str(value)


def _print_table(title: str, rows, headers=("Параметр", "Значение")) -> None:
    if not rows:
        return
    print(title)
    col1_width = max(len(headers[0]), *(len(row[0]) for row in rows))
    col2_width = max(len(headers[1]), *(len(row[1]) for row in rows))
    print(f"{headers[0].ljust(col1_width)} | {headers[1].ljust(col2_width)}")
    print(f"{'-' * col1_width}-+-{'-' * col2_width}")
    for name, value in rows:
        print(f"{name.ljust(col1_width)} | {value}")
    print()


@pkcs11_command
def show_wallet_info(pkcs11, wallet_id=0):
    """Получить подробную информацию о кошельке."""

    define_pkcs11_functions(pkcs11)

    token_info = CK_TOKEN_INFO()
    rv = pkcs11.C_GetTokenInfo(wallet_id, ctypes.byref(token_info))
    if rv == CKR_TOKEN_NOT_PRESENT:
        print('Нет подключенного кошелька, подключите кошелек')
        return
    if rv != 0:
        print(f'C_GetTokenInfo вернула ошибку: 0x{rv:08X}')
        return

    if not hasattr(pkcs11, 'C_EX_GetTokenInfoExtended'):
        print('Расширенная функция C_EX_GetTokenInfoExtended недоступна в библиотеке')
        return

    extended_info = CK_TOKEN_INFO_EXTENDED()
    extended_info.ulSizeofThisStructure = ctypes.sizeof(CK_TOKEN_INFO_EXTENDED)
    rv = pkcs11.C_EX_GetTokenInfoExtended(wallet_id, ctypes.byref(extended_info))
    if rv == CKR_TOKEN_NOT_PRESENT:
        print('Нет подключенного кошелька, подключите кошелек')
        return
    if rv != 0:
        print(f'C_EX_GetTokenInfoExtended вернула ошибку: 0x{rv:08X}')
        return

    basic_rows = [
        ('Метка', _decode_char_array(token_info.label)),
        ('Производитель', _decode_char_array(token_info.manufacturerID)),
        ('Модель', _decode_char_array(token_info.model)),
        ('Серийный номер', _decode_char_array(token_info.serialNumber)),
        ('Флаги (значение)', f"0x{token_info.flags:08X}"),
        ('Версия аппаратная', _format_version(token_info.hardwareVersion)),
        ('Версия прошивки', _format_version(token_info.firmwareVersion)),
    ]
    basic_rows = [(name, _prepare_value(value)) for name, value in basic_rows]

    pin_rows = [
        ('Макс. длина PIN (стандарт)', token_info.ulMaxPinLen),
        ('Мин. длина PIN (стандарт)', token_info.ulMinPinLen),
        ('Макс. длина PIN (пользователь)', extended_info.ulMaxUserPinLen),
        ('Мин. длина PIN (пользователь)', extended_info.ulMinUserPinLen),
        ('Макс. число попыток (пользователь)', extended_info.ulMaxUserRetryCount),
        ('Осталось попыток (пользователь)', extended_info.ulUserRetryCountLeft),
    ]
    pin_rows = [(name, _prepare_value(value)) for name, value in pin_rows]

    serial_be = bytes(extended_info.serialNumber)
    atr_bytes = bytes(extended_info.ATR)[: extended_info.ulATRLen]
    firmware_checksum = (
        'недоступно'
        if extended_info.flags & TOKEN_FLAGS_FW_CHECKSUM_UNAVAILIBLE
        else f"0x{extended_info.ulFirmwareChecksum:08X}"
    )
    if extended_info.flags & TOKEN_FLAGS_FW_CHECKSUM_INVALID:
        firmware_checksum += ' (некорректна)'

    device_rows = [
        ('Номер микропрограммы', extended_info.ulMicrocodeNumber),
        ('Номер заказа', extended_info.ulOrderNumber),
        ('Серийный номер (BE)', _format_hex_bytes(serial_be)),
        ('Всего памяти, байт', extended_info.ulTotalMemory),
        ('Свободно памяти, байт', extended_info.ulFreeMemory),
        ('ATR', _format_hex_bytes(atr_bytes)),
        ('Длина ATR', extended_info.ulATRLen),
        ('Напряжение батареи, мВ', extended_info.ulBatteryVoltage),
        ('Контрольная сумма прошивки', firmware_checksum),
    ]
    device_rows = [(name, _prepare_value(value)) for name, value in device_rows]

    flag_descriptions = [
        (TOKEN_FLAGS_USER_PIN_NOT_DEFAULT, 'Пользовательский PIN изменён'),
        (TOKEN_FLAGS_SUPPORT_JOURNAL, 'Поддерживается журнал'),
        (TOKEN_FLAGS_USER_PIN_UTF8, 'Пользовательский PIN в UTF-8'),
        (TOKEN_FLAGS_FW_CHECKSUM_UNAVAILIBLE, 'Контрольная сумма недоступна'),
        (TOKEN_FLAGS_FW_CHECKSUM_INVALID, 'Контрольная сумма некорректна'),
    ]
    flag_rows = []
    for mask, description in flag_descriptions:
        is_set = 'Да' if extended_info.flags & mask else 'Нет'
        flag_rows.append((description, is_set))

    _print_table('Основная информация о кошельке', basic_rows)
    _print_table('Параметры PIN-кода', pin_rows)
    _print_table('Информация об устройстве', device_rows)
    _print_table('Расширенные флаги', flag_rows, headers=('Флаг', 'Установлен'))


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

    if count.value == 0:
        print('Нет подключенного кошелька, подключите кошелек')
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
def list_objects(pkcs11, wallet_id=0, pin=None):
    """Выводит список ключей. Если PIN не задан, показываются только публичные ключи."""
    define_pkcs11_functions(pkcs11)

    session = ctypes.c_ulong()
    rv = pkcs11.C_OpenSession(
        wallet_id,
        CKF_SERIAL_SESSION | CKF_RW_SESSION,
        None,
        None,
        ctypes.byref(session),
    )
    if rv == CKR_TOKEN_NOT_PRESENT:
        print('Нет подключенного кошелька, подключите кошелек')
        return
    if rv != 0:
        print(f'C_OpenSession вернула ошибку: 0x{rv:08X}')
        return

    logged_in = False
    try:
        if pin:
            rv = pkcs11.C_Login(session, CKU_USER, pin.encode('utf-8'), len(pin))
            if rv != 0:
                print(f'C_Login вернула ошибку: 0x{rv:08X}')
                return
            logged_in = True
        else:
            print('Закрытые ключи не отображаются без ввода PIN-кода')

        def search_objects(obj_class):
            class_val = ctypes.c_ulong(obj_class)
            attr = CK_ATTRIBUTE()
            attr.type = CKA_CLASS
            attr.pValue = ctypes.cast(ctypes.pointer(class_val), ctypes.c_void_p)
            attr.ulValueLen = ctypes.sizeof(class_val)
            template = (CK_ATTRIBUTE * 1)(attr)

            rv = pkcs11.C_FindObjectsInit(session, template, 1)
            if rv != 0:
                print(f'C_FindObjectsInit вернула ошибку: 0x{rv:08X}')
                return []

            handles = []
            obj = ctypes.c_ulong()
            count = ctypes.c_ulong()
            while True:
                rv = pkcs11.C_FindObjects(session, ctypes.byref(obj), 1, ctypes.byref(count))
                if rv != 0 or count.value == 0:
                    break
                handles.append(obj.value)
            pkcs11.C_FindObjectsFinal(session)
            return handles

        def get_attributes(handle):
            attrs = {}
            for attr_type, attr_name in [
                (CKA_LABEL, 'CKA_LABEL'),
                (CKA_ID, 'CKA_ID'),
                (CKA_VALUE, 'CKA_VALUE'),
                (CKA_KEY_TYPE, 'CKA_KEY_TYPE'),
            ]:
                attr_template = CK_ATTRIBUTE(type=attr_type, pValue=None, ulValueLen=0)
                rv = pkcs11.C_GetAttributeValue(
                    session, ctypes.c_ulong(handle), ctypes.byref(attr_template), 1
                )
                if rv != 0 or attr_template.ulValueLen == 0:
                    continue
                buf = (ctypes.c_ubyte * attr_template.ulValueLen)()
                attr_template.pValue = ctypes.cast(buf, ctypes.c_void_p)
                rv = pkcs11.C_GetAttributeValue(
                    session, ctypes.c_ulong(handle), ctypes.byref(attr_template), 1
                )
                if rv == 0:
                    if attr_type == CKA_KEY_TYPE:
                        attrs[attr_name] = int.from_bytes(bytes(buf), sys.byteorder)
                    else:
                        attrs[attr_name] = bytes(buf)
            return attrs

        objects = {}
        for h in search_objects(CKO_PUBLIC_KEY):
            attrs = get_attributes(h)
            objects.setdefault(attrs.get('CKA_ID'), {})['public'] = (h, attrs)

        if logged_in:
            for h in search_objects(CKO_PRIVATE_KEY):
                attrs = get_attributes(h)
                objects.setdefault(attrs.get('CKA_ID'), {})['private'] = (h, attrs)

        # If both public and private parts are found, copy label from private to
        # public key when the latter lacks one.
        for pair in objects.values():
            if 'public' in pair and 'private' in pair:
                pub_attrs = pair['public'][1]
                priv_attrs = pair['private'][1]
                if 'CKA_LABEL' not in pub_attrs and 'CKA_LABEL' in priv_attrs:
                    pub_attrs['CKA_LABEL'] = priv_attrs['CKA_LABEL']

        print('Список ключей в кошельке:')
        for idx, key_id in enumerate(
            sorted(objects.keys(), key=lambda x: x or b''), start=1
        ):
            pair = objects[key_id]
            key_type = None
            if 'public' in pair and 'CKA_KEY_TYPE' in pair['public'][1]:
                key_type = pair['public'][1]['CKA_KEY_TYPE']
            elif 'private' in pair and 'CKA_KEY_TYPE' in pair['private'][1]:
                key_type = pair['private'][1]['CKA_KEY_TYPE']
            suffix = (
                f" ({key_type_description.get(key_type)})"
                if key_type in key_type_description
                else ''
            )
            print(f'  Ключ \N{numero sign}{idx}{suffix}:')
            if 'public' in pair:
                h, attrs = pair['public']
                print('    Публичный ключ')
                for name in ['CKA_LABEL', 'CKA_ID', 'CKA_VALUE']:
                    raw = attrs.get(name)
                    if raw is None and name == 'CKA_LABEL' and 'private' in pair:
                        raw = pair['private'][1].get(name)
                    if raw is not None:
                        hex_repr = format_attribute_value(raw, 'hex')
                        text_repr = format_attribute_value(raw, 'text')
                        print(f'      {name} (HEX): {hex_repr}')
                        print(f'      {name} (TEXT): {text_repr}')
            if 'private' in pair:
                h, attrs = pair['private']
                print('    Закрытый ключ')
                for name in ['CKA_LABEL', 'CKA_ID', 'CKA_VALUE']:
                    if name in attrs:
                        raw = attrs[name]
                        hex_repr = format_attribute_value(raw, 'hex')
                        text_repr = format_attribute_value(raw, 'text')
                        print(f'      {name} (HEX): {hex_repr}')
                        print(f'      {name} (TEXT): {text_repr}')
    finally:
        if logged_in:
            pkcs11.C_Logout(session)
        pkcs11.C_CloseSession(session)


@pkcs11_command
def change_pin(pkcs11, wallet_id=0, old_pin=None, new_pin=None):
    """Сменить пользовательский PIN-код токена."""
    define_pkcs11_functions(pkcs11)

    session = ctypes.c_ulong()
    rv = pkcs11.C_OpenSession(
        wallet_id,
        CKF_SERIAL_SESSION | CKF_RW_SESSION,
        None,
        None,
        ctypes.byref(session),
    )
    if rv == CKR_TOKEN_NOT_PRESENT:
        print('Нет подключенного кошелька, подключите кошелек')
        return
    if rv != 0:
        print(f'C_OpenSession вернула ошибку: 0x{rv:08X}')
        return

    logged_in = False
    try:
        if old_pin is None or new_pin is None:
            print(
                'Необходимо указать текущий и новый PIN-коды',
                file=sys.stderr,
            )
            return

        old_pin_bytes = old_pin.encode('utf-8')
        new_pin_bytes = new_pin.encode('utf-8')

        rv = pkcs11.C_Login(
            session, CKU_USER, old_pin_bytes, len(old_pin_bytes)
        )
        if rv != 0:
            print(f'C_Login вернула ошибку: 0x{rv:08X}')
            return
        logged_in = True

        rv = pkcs11.C_SetPIN(
            session,
            old_pin_bytes,
            len(old_pin_bytes),
            new_pin_bytes,
            len(new_pin_bytes),
        )
        if rv != 0:
            print(f'C_SetPIN вернула ошибку: 0x{rv:08X}')
        else:
            print('PIN-код успешно изменён.')
    finally:
        if logged_in:
            pkcs11.C_Logout(session)
        pkcs11.C_CloseSession(session)


@pkcs11_command
def generate_key_pair(pkcs11, wallet_id=0, pin=None, algorithm=None, cka_id="", cka_label=""):
    """Generate key pair on token.

    Parameters
    ----------
    cka_id: str
        Value for the ``CKA_ID`` attribute.
    cka_label: str
        Value for the ``CKA_LABEL`` attribute.
    """
    define_pkcs11_functions(pkcs11)

    session = ctypes.c_ulong()
    rv = pkcs11.C_OpenSession(
        wallet_id, CKF_SERIAL_SESSION | CKF_RW_SESSION, None, None, ctypes.byref(session)
    )
    if rv == CKR_TOKEN_NOT_PRESENT:
        print('Нет подключенного кошелька, подключите кошелек')
        return
    if rv != 0:
        print(f'C_OpenSession вернула ошибку: 0x{rv:08X}')
        return

    logged_in = False
    try:
        if not cka_id or not cka_label:
            print(
                'Необходимо указать key-id и key-label для генерации ключа',
                file=sys.stderr,
            )
            return

        if not pin:
            print(
                'Необходимо указать PIN-код для генерации ключа',
                file=sys.stderr,
            )
            return

        rv = pkcs11.C_Login(session, CKU_USER, pin.encode('utf-8'), len(pin))
        if rv != 0:
            print(f'C_Login вернула ошибку: 0x{rv:08X}')
            return
        logged_in = True

        mechanism = CK_MECHANISM(mechanism=0, pParameter=None, ulParameterLen=0)

        true_val = ctypes.c_ubyte(1)
        false_val = ctypes.c_ubyte(0)

        pub_attrs = [
            CK_ATTRIBUTE(
                type=CKA_TOKEN,
                pValue=ctypes.cast(ctypes.pointer(true_val), ctypes.c_void_p),
                ulValueLen=1,
            ),
            CK_ATTRIBUTE(
                type=CKA_PRIVATE,
                pValue=ctypes.cast(ctypes.pointer(false_val), ctypes.c_void_p),
                ulValueLen=1,
            ),
        ]

        priv_attrs = [
            CK_ATTRIBUTE(
                type=CKA_TOKEN,
                pValue=ctypes.cast(ctypes.pointer(true_val), ctypes.c_void_p),
                ulValueLen=1,
            ),
            CK_ATTRIBUTE(
                type=CKA_PRIVATE,
                pValue=ctypes.cast(ctypes.pointer(true_val), ctypes.c_void_p),
                ulValueLen=1,
            ),
        ]

        buffers = []

        if cka_id:
            id_bytes = cka_id.encode('utf-8')
            id_buf_pub = (ctypes.c_ubyte * len(id_bytes))(*id_bytes)
            id_buf_priv = (ctypes.c_ubyte * len(id_bytes))(*id_bytes)
            buffers.extend([id_buf_pub, id_buf_priv])
            pub_attrs.append(
                CK_ATTRIBUTE(
                    type=CKA_ID,
                    pValue=ctypes.cast(id_buf_pub, ctypes.c_void_p),
                    ulValueLen=len(id_bytes),
                )
            )
            priv_attrs.append(
                CK_ATTRIBUTE(
                    type=CKA_ID,
                    pValue=ctypes.cast(id_buf_priv, ctypes.c_void_p),
                    ulValueLen=len(id_bytes),
                )
            )

        if cka_label:
            label_bytes = cka_label.encode('utf-8')
            label_buf_pub = (ctypes.c_char * len(label_bytes)).from_buffer_copy(
                label_bytes
            )
            label_buf_priv = (ctypes.c_char * len(label_bytes)).from_buffer_copy(
                label_bytes
            )
            buffers.extend([label_buf_pub, label_buf_priv])
            pub_attrs.append(
                CK_ATTRIBUTE(
                    type=CKA_LABEL,
                    pValue=ctypes.cast(label_buf_pub, ctypes.c_void_p),
                    ulValueLen=len(label_bytes),
                )
            )
            priv_attrs.append(
                CK_ATTRIBUTE(
                    type=CKA_LABEL,
                    pValue=ctypes.cast(label_buf_priv, ctypes.c_void_p),
                    ulValueLen=len(label_bytes),
                )
            )

        if algorithm == 'rsa1024' or algorithm == 'rsa2048':
            mechanism.mechanism = CKM_RSA_PKCS_KEY_PAIR_GEN
            bits = 1024 if algorithm == 'rsa1024' else 2048
            bits_val = ctypes.c_ulong(bits)
            pub_attrs.append(
                CK_ATTRIBUTE(
                    type=CKA_MODULUS_BITS,
                    pValue=ctypes.cast(ctypes.pointer(bits_val), ctypes.c_void_p),
                    ulValueLen=ctypes.sizeof(bits_val),
                )
            )
            exp = (ctypes.c_ubyte * 3)(0x01, 0x00, 0x01)
            pub_attrs.append(
                CK_ATTRIBUTE(
                    type=CKA_PUBLIC_EXPONENT,
                    pValue=ctypes.cast(exp, ctypes.c_void_p),
                    ulValueLen=3,
                )
            )
        elif algorithm == 'secp256':
            mechanism.mechanism = CKM_EC_KEY_PAIR_GEN
            oid = (ctypes.c_ubyte * 10)(0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07)
            pub_attrs.append(
                CK_ATTRIBUTE(
                    type=CKA_EC_PARAMS,
                    pValue=ctypes.cast(oid, ctypes.c_void_p),
                    ulValueLen=10,
                )
            )
        elif algorithm == 'ed25519':
            mechanism.mechanism = CKM_EC_EDWARDS_KEY_PAIR_GEN
            oid = (ctypes.c_ubyte * 5)(0x06, 0x03, 0x2B, 0x65, 0x70)
            pub_attrs.append(
                CK_ATTRIBUTE(
                    type=CKA_EC_PARAMS,
                    pValue=ctypes.cast(oid, ctypes.c_void_p),
                    ulValueLen=5,
                )
            )
        elif algorithm == 'gost':
            mechanism.mechanism = CKM_GOSTR3410_KEY_PAIR_GEN
            oid = (
                ctypes.c_ubyte * 11
            )(0x06, 0x09, 0x2A, 0x85, 0x03, 0x07, 0x01, 0x02, 0x01, 0x01, 0x01)
            pub_attrs.append(
                CK_ATTRIBUTE(
                    type=CKA_GOSTR3410_PARAMS,
                    pValue=ctypes.cast(oid, ctypes.c_void_p),
                    ulValueLen=11,
                )
            )
            hash_oid = (
                ctypes.c_ubyte * 10
            )(0x06, 0x08, 0x2A, 0x85, 0x03, 0x07, 0x01, 0x02, 0x02, 0x01)
            pub_attrs.append(
                CK_ATTRIBUTE(
                    type=CKA_GOSTR3411_PARAMS,
                    pValue=ctypes.cast(hash_oid, ctypes.c_void_p),
                    ulValueLen=10,
                )
            )
            priv_attrs.append(
                CK_ATTRIBUTE(
                    type=CKA_GOSTR3411_PARAMS,
                    pValue=ctypes.cast(hash_oid, ctypes.c_void_p),
                    ulValueLen=10,
                )
            )
            priv_attrs.append(
                CK_ATTRIBUTE(
                    type=CKA_GOSTR3410_PARAMS,
                    pValue=ctypes.cast(oid, ctypes.c_void_p),
                    ulValueLen=11,
                )
            )
        else:
            print('Неверный тип ключа')
            return

        pub_template = (CK_ATTRIBUTE * len(pub_attrs))(*pub_attrs)
        priv_template = (CK_ATTRIBUTE * len(priv_attrs))(*priv_attrs)
        pub_handle = ctypes.c_ulong()
        priv_handle = ctypes.c_ulong()

        rv = pkcs11.C_GenerateKeyPair(
            session,
            ctypes.byref(mechanism),
            pub_template,
            len(pub_attrs),
            priv_template,
            len(priv_attrs),
            ctypes.byref(pub_handle),
            ctypes.byref(priv_handle),
        )

        if rv != 0:
            print(f'C_GenerateKeyPair вернула ошибку: 0x{rv:08X}')
        else:
            print('Ключевая пара успешно сгенерирована.')
    finally:
        if logged_in:
            pkcs11.C_Logout(session)
        pkcs11.C_CloseSession(session)


@pkcs11_command
def delete_key_pair(pkcs11, wallet_id=0, pin=None, number=None):
    """Delete key pair from token by its index."""
    define_pkcs11_functions(pkcs11)

    session = ctypes.c_ulong()
    rv = pkcs11.C_OpenSession(
        wallet_id, CKF_SERIAL_SESSION | CKF_RW_SESSION, None, None, ctypes.byref(session)
    )
    if rv == CKR_TOKEN_NOT_PRESENT:
        print('Нет подключенного кошелька, подключите кошелек')
        return
    if rv != 0:
        print(f'C_OpenSession вернула ошибку: 0x{rv:08X}')
        return

    try:
        if not pin:
            print('Необходимо указать PIN-код для удаления ключей', file=sys.stderr)
            return

        if number is None:
            print('Необходимо указать номер ключа для удаления', file=sys.stderr)
            return

        rv = pkcs11.C_Login(session, CKU_USER, pin.encode('utf-8'), len(pin))
        if rv != 0:
            print(f'C_Login вернула ошибку: 0x{rv:08X}')
            return

        def search_objects(obj_class):
            class_val = ctypes.c_ulong(obj_class)
            attr = CK_ATTRIBUTE(
                type=CKA_CLASS,
                pValue=ctypes.cast(ctypes.pointer(class_val), ctypes.c_void_p),
                ulValueLen=ctypes.sizeof(class_val),
            )
            template = (CK_ATTRIBUTE * 1)(attr)
            rv = pkcs11.C_FindObjectsInit(session, template, 1)
            if rv != 0:
                return []

            handles = []
            obj = ctypes.c_ulong()
            count = ctypes.c_ulong()
            while True:
                rv = pkcs11.C_FindObjects(session, ctypes.byref(obj), 1, ctypes.byref(count))
                if rv != 0 or count.value == 0:
                    break
                handles.append(obj.value)
            pkcs11.C_FindObjectsFinal(session)
            return handles

        def get_id(handle):
            attr = CK_ATTRIBUTE(type=CKA_ID, pValue=None, ulValueLen=0)
            rv = pkcs11.C_GetAttributeValue(
                session, ctypes.c_ulong(handle), ctypes.byref(attr), 1
            )
            if rv != 0 or attr.ulValueLen == 0:
                return None
            buf = (ctypes.c_ubyte * attr.ulValueLen)()
            attr.pValue = ctypes.cast(buf, ctypes.c_void_p)
            rv = pkcs11.C_GetAttributeValue(
                session, ctypes.c_ulong(handle), ctypes.byref(attr), 1
            )
            if rv != 0:
                return None
            return bytes(buf)

        objects = {}
        for h in search_objects(CKO_PUBLIC_KEY):
            key_id = get_id(h)
            objects.setdefault(key_id, {})['public'] = h

        for h in search_objects(CKO_PRIVATE_KEY):
            key_id = get_id(h)
            objects.setdefault(key_id, {})['private'] = h

        ids = sorted(objects.keys(), key=lambda x: x or b'')
        if number < 1 or number > len(ids):
            print('Ключ с таким номером не найден')
            return

        pair = objects[ids[number - 1]]
        if 'public' in pair:
            rv = pkcs11.C_DestroyObject(session, pair['public'])
            if rv != 0:
                print(f'Ошибка удаления публичного ключа: 0x{rv:08X}')
        if 'private' in pair:
            rv = pkcs11.C_DestroyObject(session, pair['private'])
            if rv != 0:
                print(f'Ошибка удаления закрытого ключа: 0x{rv:08X}')
    finally:
        pkcs11.C_Logout(session)
        pkcs11.C_CloseSession(session)
