import ctypes
import hashlib
import hmac
import sys
import unicodedata
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
    CKR_OK,
    CKR_OBJECT_HANDLE_INVALID,
    CKK_RSA,
    CKK_EC,
    CKK_EC_EDWARDS,
    CKK_EC_MONTGOMERY,
    CKK_GOSTR3410,
    CKK_VENDOR_BIP32,
    CKA_TOKEN,
    CKA_PRIVATE,
    CKA_DERIVE,
    CKA_MODULUS_BITS,
    CKA_PUBLIC_EXPONENT,
    CKA_EC_PARAMS,
    CKA_GOSTR3410_PARAMS,
    CKA_GOSTR3411_PARAMS,
    CKM_RSA_PKCS_KEY_PAIR_GEN,
    CKM_EC_KEY_PAIR_GEN,
    CKM_EC_EDWARDS_KEY_PAIR_GEN,
    CKM_GOSTR3410_KEY_PAIR_GEN,
    CKM_VENDOR_BIP32_WITH_BIP39_KEY_PAIR_GEN,
    CK_MECHANISM,
    CKU_USER,
    CK_VENDOR_BIP32_WITH_BIP39_KEY_PAIR_GEN_PARAMS,
    TOKEN_FLAGS_USER_PIN_NOT_DEFAULT,
    TOKEN_FLAGS_SUPPORT_JOURNAL,
    TOKEN_FLAGS_USER_PIN_UTF8,
    TOKEN_FLAGS_FW_CHECKSUM_UNAVAILIBLE,
    TOKEN_FLAGS_FW_CHECKSUM_INVALID,
    CKA_VENDOR_BIP39_MNEMONIC,
    CKA_VENDOR_BIP39_MNEMONIC_IS_EXTRACTABLE,
    CKA_VENDOR_BIP32_CHAINCODE,
)
from pkcs11_definitions import define_pkcs11_functions

key_type_description = {
    CKK_RSA: "RSA",
    CKK_EC: "ECDSA (bitcoin, ethereum, tron и т.д.)",
    CKK_EC_EDWARDS: "EdDSA (solana, ton и т.д.)",
    CKK_EC_MONTGOMERY: "EdDSA (solana, ton и т.д.)",
    CKK_GOSTR3410: "ГОСТ 34.10-2012",
}

SECP256R1_OID_DER = bytes(
    (
        0x06,
        0x08,
        0x2A,
        0x86,
        0x48,
        0xCE,
        0x3D,
        0x03,
        0x01,
        0x07,
    )
)


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


def _zero_bytearray(buffer) -> None:
    if buffer is None:
        return
    for idx in range(len(buffer)):
        buffer[idx] = 0


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


def safe_get_attributes(pkcs11, session, handle, attr_types):
    """Safely read a list of attributes for a PKCS#11 object.

    Returns a dictionary mapping attribute type to value. If the attributes
    cannot be retrieved (for example, because the handle is invalid), ``None``
    is returned instead of raising an exception or printing to stderr.
    """

    if handle is None:
        return None

    result = {}
    handle_obj = ctypes.c_ulong(handle)
    unavailable = ctypes.c_ulong(-1).value

    for attr_type in attr_types:
        attr_template = CK_ATTRIBUTE(type=attr_type, pValue=None, ulValueLen=0)
        rv = pkcs11.C_GetAttributeValue(
            session, handle_obj, ctypes.byref(attr_template), 1
        )
        if rv == CKR_OBJECT_HANDLE_INVALID:
            return None
        if rv != CKR_OK:
            continue

        length = attr_template.ulValueLen
        if length == unavailable:
            continue
        if length > 0:
            buffer = (ctypes.c_ubyte * length)()
            attr_template.pValue = ctypes.cast(buffer, ctypes.c_void_p)
            rv = pkcs11.C_GetAttributeValue(
                session, handle_obj, ctypes.byref(attr_template), 1
            )
            if rv == CKR_OBJECT_HANDLE_INVALID:
                return None
            if rv != CKR_OK:
                continue
            raw_value = bytes(buffer)
        else:
            raw_value = b""

        if attr_type == CKA_KEY_TYPE:
            if raw_value:
                result[attr_type] = int.from_bytes(raw_value, sys.byteorder)
        else:
            result[attr_type] = raw_value

    return result


@pkcs11_command
def show_wallet_info(pkcs11, wallet_id=0):
    """Получить подробную информацию о кошельке."""

    run_command_show_wallet_info(pkcs11, wallet_id=wallet_id)


def run_command_show_wallet_info(pkcs11, wallet_id=0):
    define_pkcs11_functions(pkcs11)

    initialized = False
    had_error = False
    try:
        rv = pkcs11.C_Initialize(None)
        if rv != CKR_OK:
            print(f'C_Initialize вернула ошибку: 0x{rv:08X}')
            had_error = True
        else:
            initialized = True

        token_info = CK_TOKEN_INFO()
        if not had_error:
            rv = pkcs11.C_GetTokenInfo(wallet_id, ctypes.byref(token_info))
            if rv == CKR_TOKEN_NOT_PRESENT:
                print('Нет подключенного кошелька, подключите кошелек')
                had_error = True
            elif rv != CKR_OK:
                print(f'C_GetTokenInfo вернула ошибку: 0x{rv:08X}')
                had_error = True

        extended_info = None
        if not had_error:
            if not hasattr(pkcs11, 'C_EX_GetTokenInfoExtended'):
                print('Расширенная функция C_EX_GetTokenInfoExtended недоступна в библиотеке')
                had_error = True
            else:
                extended_info = CK_TOKEN_INFO_EXTENDED()
                extended_info.ulSizeofThisStructure = ctypes.sizeof(
                    CK_TOKEN_INFO_EXTENDED
                )
                rv = pkcs11.C_EX_GetTokenInfoExtended(
                    wallet_id, ctypes.byref(extended_info)
                )
                if rv == CKR_TOKEN_NOT_PRESENT:
                    print('Нет подключенного кошелька, подключите кошелек')
                    had_error = True
                elif rv != CKR_OK:
                    print(
                        f'C_EX_GetTokenInfoExtended вернула ошибку: 0x{rv:08X}'
                    )
                    had_error = True

        if not had_error and extended_info is not None:
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
                (
                    'Макс. число попыток (пользователь)',
                    extended_info.ulMaxUserRetryCount,
                ),
                (
                    'Осталось попыток (пользователь)',
                    extended_info.ulUserRetryCountLeft,
                ),
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
                (
                    TOKEN_FLAGS_FW_CHECKSUM_UNAVAILIBLE,
                    'Контрольная сумма недоступна',
                ),
                (
                    TOKEN_FLAGS_FW_CHECKSUM_INVALID,
                    'Контрольная сумма некорректна',
                ),
            ]
            flag_rows = []
            for mask, description in flag_descriptions:
                is_set = 'Да' if extended_info.flags & mask else 'Нет'
                flag_rows.append((description, is_set))

            _print_table('Основная информация о кошельке', basic_rows)
            _print_table('Параметры PIN-кода', pin_rows)
            _print_table('Информация об устройстве', device_rows)
            _print_table(
                'Расширенные флаги', flag_rows, headers=('Флаг', 'Установлен')
            )
    finally:
        if initialized:
            pkcs11.C_Finalize(None)


@pkcs11_command
def library_info(pkcs11):
    run_command_library_info(pkcs11)


def run_command_library_info(pkcs11):
    define_pkcs11_functions(pkcs11)

    initialized = False
    try:
        rv = pkcs11.C_Initialize(None)
        if rv != CKR_OK:
            print(f'C_Initialize вернула ошибку: 0x{rv:08X}')
        else:
            initialized = True
            info = CK_INFO()
            rv = pkcs11.C_GetInfo(ctypes.byref(info))
            if rv != CKR_OK:
                print(f'C_GetInfo вернула ошибку: 0x{rv:08X}')
            else:
                version = (
                    f'{info.cryptokiVersion.major}.{info.cryptokiVersion.minor}'
                )
                libver = (
                    f'{info.libraryVersion.major}.{info.libraryVersion.minor}'
                )
                manuf = info.manufacturerID.decode('utf-8', errors='ignore')
                desc = info.libraryDescription.decode('utf-8', errors='ignore')
                print('Информация о PKCS#11 библиотеке:')
                print(f'  Cryptoki Version:    {version}')
                print(f'  Library Description: {desc}')
                print(f'  Manufacturer ID:     {manuf}')
                print(f'  Library Version:     {libver}')
    finally:
        if initialized:
            pkcs11.C_Finalize(None)

@pkcs11_command
def list_slots(pkcs11):
    """Выводит список доступных слотов."""
    run_command_list_slots(pkcs11)


def run_command_list_slots(pkcs11):
    define_pkcs11_functions(pkcs11)

    initialized = False
    try:
        rv = pkcs11.C_Initialize(None)
        if rv != CKR_OK:
            print(f'C_Initialize вернула ошибку: 0x{rv:08X}')
        else:
            initialized = True
            count = ctypes.c_ulong()
            rv = pkcs11.C_GetSlotList(False, None, ctypes.byref(count))
            if rv != CKR_OK:
                print(f'C_GetSlotList вернула ошибку: 0x{rv:08X}')
            else:
                slots = (ctypes.c_ulong * count.value)()
                rv = pkcs11.C_GetSlotList(False, slots, ctypes.byref(count))
                if rv != CKR_OK:
                    print(f'C_GetSlotList вернула ошибку: 0x{rv:08X}')
                else:
                    print('Список доступных слотов:')
                    for slot_id in slots:
                        print(f'  Слот ID: {slot_id}')
    finally:
        if initialized:
            pkcs11.C_Finalize(None)

@pkcs11_command
def list_wallets(pkcs11):
    """Выводит список доступных кошельков (токенов)."""
    run_command_list_wallets(pkcs11)


def run_command_list_wallets(pkcs11):
    define_pkcs11_functions(pkcs11)

    initialized = False
    try:
        rv = pkcs11.C_Initialize(None)
        if rv != CKR_OK:
            print(f'C_Initialize вернула ошибку: 0x{rv:08X}')
        else:
            initialized = True
            count = ctypes.c_ulong()
            rv = pkcs11.C_GetSlotList(True, None, ctypes.byref(count))
            if rv != CKR_OK:
                print(f'C_GetSlotList вернула ошибку: 0x{rv:08X}')
            elif count.value == 0:
                print('Нет подключенного кошелька, подключите кошелек')
            else:
                slots = (ctypes.c_ulong * count.value)()
                rv = pkcs11.C_GetSlotList(True, slots, ctypes.byref(count))
                if rv != CKR_OK:
                    print(f'C_GetSlotList вернула ошибку: 0x{rv:08X}')
                else:
                    print('Список доступных кошельков:')
                    for slot_id in slots:
                        token_info = CK_TOKEN_INFO()
                        rv = pkcs11.C_GetTokenInfo(
                            slot_id, ctypes.byref(token_info)
                        )
                        if rv == CKR_OK:
                            label = token_info.label.decode(
                                'utf-8', errors='ignore'
                            ).strip()
                            manufacturer = token_info.manufacturerID.decode(
                                'utf-8', errors='ignore'
                            ).strip()
                            model = token_info.model.decode(
                                'utf-8', errors='ignore'
                            ).strip()
                            serial = token_info.serialNumber.decode(
                                'utf-8', errors='ignore'
                            ).strip()
                            print(f'  Кошелёк в слоте {slot_id}:')
                            print(f'    Метка: {label}')
                            print(f'    Производитель: {manufacturer}')
                            print(f'    Модель: {model}')
                            print(f'    Серийный номер: {serial}')
                        else:
                            print(f'  Слот {slot_id} не содержит кошелька.')
    finally:
        if initialized:
            pkcs11.C_Finalize(None)

@pkcs11_command
def list_keys(pkcs11, wallet_id=0, pin=None):
    """Выводит список ключей. Если PIN не задан, показываются только публичные ключи."""
    run_command_list_keys(pkcs11, wallet_id=wallet_id, pin=pin)


def run_command_list_keys(pkcs11, wallet_id=0, pin=None):
    define_pkcs11_functions(pkcs11)

    session = ctypes.c_ulong()
    initialized = False
    session_opened = False
    logged_in = False
    had_error = False

    try:
        rv = pkcs11.C_Initialize(None)
        if rv != CKR_OK:
            print(f'C_Initialize вернула ошибку: 0x{rv:08X}')
            had_error = True
        else:
            initialized = True

        if not had_error:
            rv = pkcs11.C_OpenSession(
                wallet_id,
                CKF_SERIAL_SESSION | CKF_RW_SESSION,
                None,
                None,
                ctypes.byref(session),
            )
            if rv == CKR_TOKEN_NOT_PRESENT:
                print('Нет подключенного кошелька, подключите кошелек')
                had_error = True
            elif rv != CKR_OK:
                print(f'C_OpenSession вернула ошибку: 0x{rv:08X}')
                had_error = True
            else:
                session_opened = True

        if session_opened:
            if pin:
                pin_bytes = pin.encode('utf-8')
                rv = pkcs11.C_Login(session, CKU_USER, pin_bytes, len(pin_bytes))
                if rv != CKR_OK:
                    print(f'C_Login вернула ошибку: 0x{rv:08X}')
                    had_error = True
                else:
                    logged_in = True
            else:
                print('Закрытые ключи не отображаются без ввода PIN-кода')

        objects = []

        if session_opened and not had_error:

            def search_objects(obj_class, extra_attrs=None):
                handles = []
                class_val = ctypes.c_ulong(obj_class)
                attrs = [
                    CK_ATTRIBUTE(
                        type=CKA_CLASS,
                        pValue=ctypes.cast(
                            ctypes.pointer(class_val), ctypes.c_void_p
                        ),
                        ulValueLen=ctypes.sizeof(class_val),
                    )
                ]
                buffers = [class_val]

                if extra_attrs:
                    for attr_type, attr_value in extra_attrs:
                        if attr_value is None:
                            continue
                        if isinstance(attr_value, str):
                            attr_value = attr_value.encode('utf-8')
                        attr_value = bytes(attr_value)
                        buf = (ctypes.c_ubyte * len(attr_value))()
                        buf[: len(attr_value)] = attr_value
                        attrs.append(
                            CK_ATTRIBUTE(
                                type=attr_type,
                                pValue=ctypes.cast(buf, ctypes.c_void_p),
                                ulValueLen=len(attr_value),
                            )
                        )
                        buffers.append(buf)

                template = (CK_ATTRIBUTE * len(attrs))(*attrs)

                rv_local = pkcs11.C_FindObjectsInit(session, template, len(attrs))
                if rv_local != CKR_OK:
                    print(f'C_FindObjectsInit вернула ошибку: 0x{rv_local:08X}')
                    return handles

                obj = ctypes.c_ulong()
                count = ctypes.c_ulong()
                while True:
                    rv_local = pkcs11.C_FindObjects(
                        session, ctypes.byref(obj), 1, ctypes.byref(count)
                    )
                    if rv_local != CKR_OK:
                        print(f'C_FindObjects вернула ошибку: 0x{rv_local:08X}')
                        break
                    if count.value == 0:
                        break
                    handles.append(obj.value)

                rv_final = pkcs11.C_FindObjectsFinal(session)
                if rv_final != CKR_OK:
                    print(f'C_FindObjectsFinal вернула ошибку: 0x{rv_final:08X}')

                return handles

            def collect_attributes(handle):
                attr_map = safe_get_attributes(
                    pkcs11,
                    session,
                    handle,
                    [CKA_LABEL, CKA_ID, CKA_VALUE, CKA_KEY_TYPE],
                )
                if attr_map is None:
                    return None

                result = {}
                if CKA_LABEL in attr_map and attr_map[CKA_LABEL] is not None:
                    result['CKA_LABEL'] = attr_map[CKA_LABEL]
                if CKA_ID in attr_map and attr_map[CKA_ID] is not None:
                    result['CKA_ID'] = attr_map[CKA_ID]
                if CKA_VALUE in attr_map and attr_map[CKA_VALUE] is not None:
                    result['CKA_VALUE'] = attr_map[CKA_VALUE]
                if CKA_KEY_TYPE in attr_map and attr_map[CKA_KEY_TYPE] is not None:
                    result['CKA_KEY_TYPE'] = attr_map[CKA_KEY_TYPE]

                return result

            def add_object(kind, handle, attrs, key_id_override=None):
                key_id = key_id_override
                if key_id is None and attrs and 'CKA_ID' in attrs:
                    key_id = attrs['CKA_ID']
                for entry in objects:
                    if entry['key_id'] == key_id and kind not in entry:
                        entry[kind] = (handle, attrs)
                        return entry
                entry = {'key_id': key_id, kind: (handle, attrs)}
                objects.append(entry)
                return entry

            public_attrs_by_handle = {}
            public_handles_by_id = {}
            public_order = []

            for handle in search_objects(CKO_PUBLIC_KEY):
                attrs = collect_attributes(handle)
                public_attrs_by_handle[handle] = attrs
                if attrs and 'CKA_ID' in attrs:
                    public_handles_by_id.setdefault(attrs['CKA_ID'], []).append(handle)
                public_order.append(handle)
                add_object('public', handle, attrs)

            def find_public_key_by_id(key_id):
                if key_id is None:
                    return None
                handles = public_handles_by_id.get(key_id)
                if not handles:
                    return None
                return handles.pop(0)

            seen_public_handles = set()

            if logged_in:
                for handle in search_objects(CKO_PRIVATE_KEY):
                    attrs = collect_attributes(handle)
                    entry = add_object('private', handle, attrs)
                    key_id = entry['key_id']
                    if key_id is None and attrs and 'CKA_ID' in attrs:
                        key_id = attrs['CKA_ID']
                        entry['key_id'] = key_id

                    pub_handle = None
                    if attrs and 'CKA_ID' in attrs:
                        pub_handle = find_public_key_by_id(attrs['CKA_ID'])
                    if pub_handle is not None:
                        seen_public_handles.add(pub_handle)
                        entry['public'] = (
                            pub_handle,
                            public_attrs_by_handle.get(pub_handle),
                        )
                    elif 'public' in entry:
                        # keep previously collected public data if available
                        pass

            for handle in public_order:
                if handle in seen_public_handles:
                    continue
                attrs = public_attrs_by_handle.get(handle)
                add_object('public', handle, attrs)

            print('Список ключей в кошельке:')
            sorted_pairs = sorted(
                enumerate(objects),
                key=lambda item: ((item[1]['key_id'] or b''), item[0]),
            )
            for idx, pair in enumerate(sorted_pairs, start=1):
                pair = pair[1]
                key_type = None
                public_entry = pair.get('public')
                if (
                    public_entry
                    and public_entry[1] is not None
                    and 'CKA_KEY_TYPE' in public_entry[1]
                ):
                    key_type = public_entry[1]['CKA_KEY_TYPE']
                private_entry = pair.get('private')
                if key_type is None and private_entry and private_entry[1] and 'CKA_KEY_TYPE' in private_entry[1]:
                    key_type = private_entry[1]['CKA_KEY_TYPE']
                suffix = (
                    f" ({key_type_description.get(key_type)})"
                    if key_type in key_type_description
                    else ''
                )
                print(f'  Ключ \N{numero sign}{idx} (key-number={idx}){suffix}:')
                if public_entry and public_entry[1] is not None:
                    _, attrs = public_entry
                    print('    Публичный ключ')
                    for name in ['CKA_LABEL', 'CKA_ID', 'CKA_VALUE']:
                        raw = attrs.get(name)
                        if raw is None and name == 'CKA_LABEL' and private_entry and private_entry[1]:
                            raw = private_entry[1].get(name)
                        if raw is not None:
                            hex_repr = format_attribute_value(raw, 'hex')
                            text_repr = format_attribute_value(raw, 'text')
                            print(f'      {name} (HEX): {hex_repr}')
                            print(f'      {name} (TEXT): {text_repr}')
                else:
                    print('  предупреждение: отсутствует открытый ключ')
                if 'private' in pair:
                    _, attrs = pair['private']
                    print('    Закрытый ключ')
                    if attrs is not None:
                        for name in ['CKA_LABEL', 'CKA_ID', 'CKA_VALUE']:
                            if name in attrs:
                                raw = attrs[name]
                                hex_repr = format_attribute_value(raw, 'hex')
                                text_repr = format_attribute_value(raw, 'text')
                                print(f'      {name} (HEX): {hex_repr}')
                                print(f'      {name} (TEXT): {text_repr}')
                    else:
                        print('      не удалось прочитать атрибуты приватного ключа')
    finally:
        if logged_in:
            pkcs11.C_Logout(session)
        if session_opened:
            pkcs11.C_CloseSession(session)
        if initialized:
            pkcs11.C_Finalize(None)


@pkcs11_command
def change_pin(pkcs11, wallet_id=0, old_pin=None, new_pin=None):
    """Сменить пользовательский PIN-код токена."""
    run_command_change_pin(
        pkcs11, wallet_id=wallet_id, old_pin=old_pin, new_pin=new_pin
    )


def run_command_change_pin(pkcs11, wallet_id=0, old_pin=None, new_pin=None):
    define_pkcs11_functions(pkcs11)

    session = ctypes.c_ulong()
    initialized = False
    session_opened = False
    logged_in = False
    had_error = False

    try:
        rv = pkcs11.C_Initialize(None)
        if rv != CKR_OK:
            print(f'C_Initialize вернула ошибку: 0x{rv:08X}')
            had_error = True
        else:
            initialized = True

        if not had_error:
            rv = pkcs11.C_OpenSession(
                wallet_id,
                CKF_SERIAL_SESSION | CKF_RW_SESSION,
                None,
                None,
                ctypes.byref(session),
            )
            if rv == CKR_TOKEN_NOT_PRESENT:
                print('Нет подключенного кошелька, подключите кошелек')
                had_error = True
            elif rv != CKR_OK:
                print(f'C_OpenSession вернула ошибку: 0x{rv:08X}')
                had_error = True
            else:
                session_opened = True

        if session_opened:
            if old_pin is None or new_pin is None:
                print(
                    'Необходимо указать текущий и новый PIN-коды',
                    file=sys.stderr,
                )
                had_error = True
            else:
                old_pin_bytes = old_pin.encode('utf-8')
                new_pin_bytes = new_pin.encode('utf-8')

                rv = pkcs11.C_Login(
                    session, CKU_USER, old_pin_bytes, len(old_pin_bytes)
                )
                if rv != CKR_OK:
                    print(f'C_Login вернула ошибку: 0x{rv:08X}')
                    had_error = True
                else:
                    logged_in = True
                    rv = pkcs11.C_SetPIN(
                        session,
                        old_pin_bytes,
                        len(old_pin_bytes),
                        new_pin_bytes,
                        len(new_pin_bytes),
                    )
                    if rv != CKR_OK:
                        print(f'C_SetPIN вернула ошибку: 0x{rv:08X}')
                    else:
                        print('PIN-код успешно изменён.')
    finally:
        if logged_in:
            pkcs11.C_Logout(session)
        if session_opened:
            pkcs11.C_CloseSession(session)
        if initialized:
            pkcs11.C_Finalize(None)


@pkcs11_command
def import_keys(
    pkcs11,
    wallet_id=0,
    pin=None,
    mnemonic=None,
    cka_id="",
    cka_label="",
):
    """Импортировать master node HD-дерева по мнемонической фразе."""
    run_command_import_keys(
        pkcs11,
        wallet_id=wallet_id,
        pin=pin,
        mnemonic=mnemonic,
        cka_id=cka_id,
        cka_label=cka_label,
    )


def run_command_import_keys(
    pkcs11,
    wallet_id=0,
    pin=None,
    mnemonic=None,
    cka_id="",
    cka_label="",
):
    define_pkcs11_functions(pkcs11)

    session = ctypes.c_ulong()
    initialized = False
    session_opened = False
    logged_in = False
    had_error = False

    mnemonic_bytes = None
    seed = None
    hmac_result = None
    master_priv = None
    chain_code = None
    master_priv_buf = None
    chain_code_buf = None
    ec_params_buf = None
    id_buf = None
    label_buf = None

    try:
        rv = pkcs11.C_Initialize(None)
        if rv != CKR_OK:
            print(f'C_Initialize вернула ошибку: 0x{rv:08X}')
            had_error = True
        else:
            initialized = True

        if not had_error:
            rv = pkcs11.C_OpenSession(
                wallet_id,
                CKF_SERIAL_SESSION | CKF_RW_SESSION,
                None,
                None,
                ctypes.byref(session),
            )
            if rv == CKR_TOKEN_NOT_PRESENT:
                print('Нет подключенного кошелька, подключите кошелек')
                had_error = True
            elif rv != CKR_OK:
                print(f'C_OpenSession вернула ошибку: 0x{rv:08X}')
                had_error = True
            else:
                session_opened = True

        if session_opened:
            if not pin:
                print(
                    'Необходимо указать PIN-код для импорта ключей',
                    file=sys.stderr,
                )
                had_error = True
            if mnemonic is None:
                print(
                    'Необходимо указать мнемоническую фразу для импорта ключей',
                    file=sys.stderr,
                )
                had_error = True

        if session_opened and not had_error:
            sanitized = " ".join(mnemonic.strip().split())
            if not sanitized:
                print('Мнемоническая фраза не должна быть пустой', file=sys.stderr)
                had_error = True
            else:
                words = sanitized.split(" ")
                if len(words) not in {12, 15, 18, 21, 24}:
                    print(
                        'Мнемоническая фраза должна содержать 12, 15, 18, 21 или 24 слова',
                        file=sys.stderr,
                    )
                    had_error = True
                else:
                    normalized = unicodedata.normalize("NFKD", sanitized)
                    mnemonic_bytes = bytearray(normalized.encode('utf-8'))
                    seed = bytearray(
                        hashlib.pbkdf2_hmac(
                            'sha512', mnemonic_bytes, b'mnemonic', 2048, dklen=64
                        )
                    )
                    hmac_result = bytearray(
                        hmac.new(b'Bitcoin seed', seed, hashlib.sha512).digest()
                    )
                    master_priv = bytearray(hmac_result[:32])
                    chain_code = bytearray(hmac_result[32:])

        if session_opened and not had_error:
            pin_bytes = pin.encode('utf-8')
            rv = pkcs11.C_Login(session, CKU_USER, pin_bytes, len(pin_bytes))
            if rv != CKR_OK:
                print(f'C_Login вернула ошибку: 0x{rv:08X}')
                had_error = True
            else:
                logged_in = True

        if logged_in and not had_error:
            if len(master_priv) != 32 or len(chain_code) != 32:
                print('Некорректная длина master key или chain code', file=sys.stderr)
                had_error = True
            else:
                ck_true = ctypes.c_ubyte(1)
                cko_private_key = ctypes.c_ulong(CKO_PRIVATE_KEY)
                key_type = ctypes.c_ulong(CKK_VENDOR_BIP32)
                master_priv_buf = (ctypes.c_ubyte * len(master_priv))(*master_priv)
                chain_code_buf = (ctypes.c_ubyte * len(chain_code))(*chain_code)
                ec_params_buf = (ctypes.c_ubyte * len(SECP256R1_OID_DER))(
                    *SECP256R1_OID_DER
                )

                attributes = [
                    CK_ATTRIBUTE(
                        type=CKA_CLASS,
                        pValue=ctypes.cast(
                            ctypes.pointer(cko_private_key), ctypes.c_void_p
                        ),
                        ulValueLen=ctypes.sizeof(cko_private_key),
                    ),
                    CK_ATTRIBUTE(
                        type=CKA_KEY_TYPE,
                        pValue=ctypes.cast(ctypes.pointer(key_type), ctypes.c_void_p),
                        ulValueLen=ctypes.sizeof(key_type),
                    ),
                    CK_ATTRIBUTE(
                        type=CKA_VALUE,
                        pValue=ctypes.cast(master_priv_buf, ctypes.c_void_p),
                        ulValueLen=len(master_priv),
                    ),
                    CK_ATTRIBUTE(
                        type=CKA_VENDOR_BIP32_CHAINCODE,
                        pValue=ctypes.cast(chain_code_buf, ctypes.c_void_p),
                        ulValueLen=len(chain_code),
                    ),
                    CK_ATTRIBUTE(
                        type=CKA_TOKEN,
                        pValue=ctypes.cast(ctypes.pointer(ck_true), ctypes.c_void_p),
                        ulValueLen=1,
                    ),
                    CK_ATTRIBUTE(
                        type=CKA_PRIVATE,
                        pValue=ctypes.cast(ctypes.pointer(ck_true), ctypes.c_void_p),
                        ulValueLen=1,
                    ),
                    CK_ATTRIBUTE(
                        type=CKA_DERIVE,
                        pValue=ctypes.cast(ctypes.pointer(ck_true), ctypes.c_void_p),
                        ulValueLen=1,
                    ),
                    CK_ATTRIBUTE(
                        type=CKA_EC_PARAMS,
                        pValue=ctypes.cast(ec_params_buf, ctypes.c_void_p),
                        ulValueLen=len(SECP256R1_OID_DER),
                    ),
                ]

                if cka_id:
                    id_bytes = cka_id.encode('utf-8')
                    id_buf = (ctypes.c_ubyte * len(id_bytes))(*id_bytes)
                    attributes.append(
                        CK_ATTRIBUTE(
                            type=CKA_ID,
                            pValue=ctypes.cast(id_buf, ctypes.c_void_p),
                            ulValueLen=len(id_bytes),
                        )
                    )

                if cka_label:
                    label_bytes = cka_label.encode('utf-8')
                    label_buf = ctypes.create_string_buffer(label_bytes)
                    attributes.append(
                        CK_ATTRIBUTE(
                            type=CKA_LABEL,
                            pValue=ctypes.cast(label_buf, ctypes.c_void_p),
                            ulValueLen=len(label_bytes),
                        )
                    )

                private_template = (CK_ATTRIBUTE * len(attributes))(*attributes)
                handle = ctypes.c_ulong()
                rv = pkcs11.C_CreateObject(
                    session,
                    private_template,
                    len(attributes),
                    ctypes.byref(handle),
                )

                if rv != CKR_OK:
                    print(f'Ошибка создания объекта: 0x{rv:08X}')
                else:
                    print('Мастер-ключ успешно импортирован.')
    finally:
        if logged_in:
            pkcs11.C_Logout(session)
        if session_opened:
            pkcs11.C_CloseSession(session)
        if initialized:
            pkcs11.C_Finalize(None)

        _zero_bytearray(mnemonic_bytes)
        _zero_bytearray(seed)
        _zero_bytearray(hmac_result)
        _zero_bytearray(master_priv)
        _zero_bytearray(chain_code)

        if master_priv_buf is not None:
            ctypes.memset(master_priv_buf, 0, ctypes.sizeof(master_priv_buf))
        if chain_code_buf is not None:
            ctypes.memset(chain_code_buf, 0, ctypes.sizeof(chain_code_buf))
        if ec_params_buf is not None:
            ctypes.memset(ec_params_buf, 0, ctypes.sizeof(ec_params_buf))
        if id_buf is not None:
            ctypes.memset(id_buf, 0, ctypes.sizeof(id_buf))
        if label_buf is not None:
            ctypes.memset(label_buf, 0, ctypes.sizeof(label_buf))


@pkcs11_command
def generate_key_pair(
    pkcs11,
    wallet_id=0,
    pin=None,
    algorithm=None,
    cka_id="",
    cka_label="",
    get_mnemonic=False,
):
    """Generate key pair on token.

    Parameters
    ----------
    cka_id: str
        Value for the ``CKA_ID`` attribute.
    cka_label: str
        Value for the ``CKA_LABEL`` attribute.
    """
    run_command_generate_key_pair(
        pkcs11,
        wallet_id=wallet_id,
        pin=pin,
        algorithm=algorithm,
        cka_id=cka_id,
        cka_label=cka_label,
        get_mnemonic=get_mnemonic,
    )


def run_command_generate_key_pair(
    pkcs11,
    wallet_id=0,
    pin=None,
    algorithm=None,
    cka_id="",
    cka_label="",
    get_mnemonic=False,
):
    define_pkcs11_functions(pkcs11)

    session = ctypes.c_ulong()
    initialized = False
    session_opened = False
    logged_in = False
    had_error = False
    buffers = []

    try:
        rv = pkcs11.C_Initialize(None)
        if rv != CKR_OK:
            print(f'C_Initialize вернула ошибку: 0x{rv:08X}')
            had_error = True
        else:
            initialized = True

        if not had_error:
            rv = pkcs11.C_OpenSession(
                wallet_id,
                CKF_SERIAL_SESSION | CKF_RW_SESSION,
                None,
                None,
                ctypes.byref(session),
            )
            if rv == CKR_TOKEN_NOT_PRESENT:
                print('Нет подключенного кошелька, подключите кошелек')
                had_error = True
            elif rv != CKR_OK:
                print(f'C_OpenSession вернула ошибку: 0x{rv:08X}')
                had_error = True
            else:
                session_opened = True

        if session_opened:
            if not cka_id or not cka_label:
                print(
                    'Необходимо указать key-id и key-label для генерации ключа',
                    file=sys.stderr,
                )
                had_error = True
            if not pin:
                print(
                    'Необходимо указать PIN-код для генерации ключа',
                    file=sys.stderr,
                )
                had_error = True
            if get_mnemonic and algorithm != 'secp256':
                print(
                    '--get-mnemonic доступен только для алгоритма secp256',
                    file=sys.stderr,
                )
                had_error = True
            if algorithm not in {'rsa1024', 'rsa2048', 'secp256', 'ed25519', 'gost'}:
                print('Неверный тип ключа')
                had_error = True

        if session_opened and not had_error:
            pin_bytes = pin.encode('utf-8')
            rv = pkcs11.C_Login(session, CKU_USER, pin_bytes, len(pin_bytes))
            if rv != CKR_OK:
                print(f'C_Login вернула ошибку: 0x{rv:08X}')
                had_error = True
            else:
                logged_in = True

        mnemonic_attr = None
        if logged_in and not had_error:
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

            if algorithm in {'rsa1024', 'rsa2048'}:
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
                if get_mnemonic:
                    mechanism.mechanism = CKM_VENDOR_BIP32_WITH_BIP39_KEY_PAIR_GEN
                    empty_passphrase = (ctypes.c_ubyte * 1)()
                    buffers.append(empty_passphrase)
                    mech_params = CK_VENDOR_BIP32_WITH_BIP39_KEY_PAIR_GEN_PARAMS()
                    mech_params.pPassphrase = ctypes.cast(
                        empty_passphrase, ctypes.c_void_p
                    )
                    mech_params.ulPassphraseLen = 0
                    mech_params.ulMnemonicLength = 24
                    buffers.append(mech_params)
                    mechanism.pParameter = ctypes.cast(
                        ctypes.pointer(mech_params), ctypes.c_void_p
                    )
                    mechanism.ulParameterLen = ctypes.sizeof(mech_params)
                else:
                    mechanism.mechanism = CKM_EC_KEY_PAIR_GEN
                    mechanism.pParameter = None
                    mechanism.ulParameterLen = 0
                oid = (ctypes.c_ubyte * len(SECP256R1_OID_DER))(*SECP256R1_OID_DER)
                pub_attrs.append(
                    CK_ATTRIBUTE(
                        type=CKA_EC_PARAMS,
                        pValue=ctypes.cast(oid, ctypes.c_void_p),
                        ulValueLen=len(SECP256R1_OID_DER),
                    )
                )
                key_type_pub = ctypes.c_ulong(CKK_EC)
                key_type_priv = ctypes.c_ulong(CKK_EC)
                buffers.extend([key_type_pub, key_type_priv])
                pub_attrs.append(
                    CK_ATTRIBUTE(
                        type=CKA_KEY_TYPE,
                        pValue=ctypes.cast(
                            ctypes.pointer(key_type_pub), ctypes.c_void_p
                        ),
                        ulValueLen=ctypes.sizeof(key_type_pub),
                    )
                )
                priv_attrs.append(
                    CK_ATTRIBUTE(
                        type=CKA_KEY_TYPE,
                        pValue=ctypes.cast(
                            ctypes.pointer(key_type_priv), ctypes.c_void_p
                        ),
                        ulValueLen=ctypes.sizeof(key_type_priv),
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

            if get_mnemonic and algorithm == 'secp256':
                bip32_key_type = ctypes.c_ulong(CKK_VENDOR_BIP32)
                buffers.append(bip32_key_type)
                for attr_list in (pub_attrs, priv_attrs):
                    for attr in attr_list:
                        if attr.type == CKA_KEY_TYPE:
                            attr.pValue = ctypes.cast(
                                ctypes.pointer(bip32_key_type), ctypes.c_void_p
                            )
                            attr.ulValueLen = ctypes.sizeof(bip32_key_type)

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

            if rv != CKR_OK:
                print(f'Ошибка генерации ключевой пары: 0x{rv:08X}')
            else:
                print('Ключевая пара успешно сгенерирована.')
                if get_mnemonic:
                    mnemonic_attr = CK_ATTRIBUTE(
                        type=CKA_VENDOR_BIP39_MNEMONIC,
                        pValue=None,
                        ulValueLen=0,
                    )
                    rv_attr = pkcs11.C_GetAttributeValue(
                        session,
                        priv_handle.value,
                        ctypes.byref(mnemonic_attr),
                        1,
                    )
                    if rv_attr != CKR_OK:
                        print(
                            f'Ошибка получения атрибута: 0x{rv_attr:08X}',
                            file=sys.stderr,
                        )
                    elif mnemonic_attr.ulValueLen == 0:
                        print(
                            'Мнемоническая фраза не возвращена токеном.',
                            file=sys.stderr,
                        )
                    else:
                        mnemonic_buf = (ctypes.c_char * mnemonic_attr.ulValueLen)()
                        mnemonic_attr.pValue = ctypes.cast(
                            mnemonic_buf, ctypes.c_void_p
                        )
                        rv_attr = pkcs11.C_GetAttributeValue(
                            session,
                            priv_handle.value,
                            ctypes.byref(mnemonic_attr),
                            1,
                        )
                        if rv_attr != CKR_OK:
                            print(
                                f'Ошибка получения атрибута: 0x{rv_attr:08X}',
                                file=sys.stderr,
                            )
                        else:
                            mnemonic_bytes = ctypes.string_at(
                                mnemonic_attr.pValue, mnemonic_attr.ulValueLen
                            )
                            mnemonic_text = mnemonic_bytes.decode(
                                'utf-8', errors='replace'
                            )
                            print("\n=============================================")
                            print(
                                'ЗАПИШИТЕ МНЕМОНИЧЕСКУЮ ФРАЗУ И СОХРАНИТЕ ЕЁ.'
                            )
                            print(
                                'ПОТЕРЯВ ФРАЗУ ВЫ НЕВОССТАНОВИМО ПОТЕРЯЕТЕ ДОСТУП К КЛЮЧАМ.\n'
                            )
                            print(mnemonic_text)
                            print('=============================================\n')

                            ck_false_local = ctypes.c_ubyte(0)
                            lock_attr = CK_ATTRIBUTE(
                                type=CKA_VENDOR_BIP39_MNEMONIC_IS_EXTRACTABLE,
                                pValue=ctypes.cast(
                                    ctypes.pointer(ck_false_local), ctypes.c_void_p
                                ),
                                ulValueLen=1,
                            )
                            rv_lock = pkcs11.C_SetAttributeValue(
                                session,
                                priv_handle.value,
                                ctypes.byref(lock_attr),
                                1,
                            )
                            if rv_lock != CKR_OK:
                                print(
                                    f'Ошибка установки атрибутов: 0x{rv_lock:08X}',
                                    file=sys.stderr,
                                )

                            ctypes.memset(
                                mnemonic_attr.pValue, 0, mnemonic_attr.ulValueLen
                            )
    finally:
        if logged_in:
            pkcs11.C_Logout(session)
        if session_opened:
            pkcs11.C_CloseSession(session)
        if initialized:
            pkcs11.C_Finalize(None)


@pkcs11_command
def delete_key_pair(pkcs11, wallet_id=0, pin=None, key_number=None):
    """Delete key pair from token by its index (``key-number``)."""
    run_command_delete_key_pair(
        pkcs11, wallet_id=wallet_id, pin=pin, key_number=key_number
    )


def run_command_delete_key_pair(pkcs11, wallet_id=0, pin=None, key_number=None):
    define_pkcs11_functions(pkcs11)

    session = ctypes.c_ulong()
    initialized = False
    session_opened = False
    logged_in = False
    had_error = False

    try:
        rv = pkcs11.C_Initialize(None)
        if rv != CKR_OK:
            print(f'C_Initialize вернула ошибку: 0x{rv:08X}')
            had_error = True
        else:
            initialized = True

        if not had_error:
            rv = pkcs11.C_OpenSession(
                wallet_id,
                CKF_SERIAL_SESSION | CKF_RW_SESSION,
                None,
                None,
                ctypes.byref(session),
            )
            if rv == CKR_TOKEN_NOT_PRESENT:
                print('Нет подключенного кошелька, подключите кошелек')
                had_error = True
            elif rv != CKR_OK:
                print(f'C_OpenSession вернула ошибку: 0x{rv:08X}')
                had_error = True
            else:
                session_opened = True

        if session_opened:
            if not pin:
                print('Необходимо указать PIN-код для удаления ключей', file=sys.stderr)
                had_error = True
            if key_number is None:
                print(
                    'Необходимо указать параметр --key-number для удаления ключа',
                    file=sys.stderr,
                )
                had_error = True

        if session_opened and not had_error:
            rv = pkcs11.C_Login(session, CKU_USER, pin.encode('utf-8'), len(pin))
            if rv != CKR_OK:
                print(f'C_Login вернула ошибку: 0x{rv:08X}')
                had_error = True
            else:
                logged_in = True

        if logged_in and not had_error:

            def search_objects(obj_class):
                handles = []
                class_val = ctypes.c_ulong(obj_class)
                attr = CK_ATTRIBUTE(
                    type=CKA_CLASS,
                    pValue=ctypes.cast(ctypes.pointer(class_val), ctypes.c_void_p),
                    ulValueLen=ctypes.sizeof(class_val),
                )
                template = (CK_ATTRIBUTE * 1)(attr)
                rv_local = pkcs11.C_FindObjectsInit(session, template, 1)
                if rv_local != CKR_OK:
                    print(f'C_FindObjectsInit вернула ошибку: 0x{rv_local:08X}')
                    return handles

                obj = ctypes.c_ulong()
                count = ctypes.c_ulong()
                while True:
                    rv_local = pkcs11.C_FindObjects(
                        session, ctypes.byref(obj), 1, ctypes.byref(count)
                    )
                    if rv_local != CKR_OK:
                        print(f'C_FindObjects вернула ошибку: 0x{rv_local:08X}')
                        break
                    if count.value == 0:
                        break
                    handles.append(obj.value)

                rv_final = pkcs11.C_FindObjectsFinal(session)
                if rv_final != CKR_OK:
                    print(f'C_FindObjectsFinal вернула ошибку: 0x{rv_final:08X}')

                return handles

            def get_id(handle):
                attr = CK_ATTRIBUTE(type=CKA_ID, pValue=None, ulValueLen=0)
                rv_local = pkcs11.C_GetAttributeValue(
                    session, ctypes.c_ulong(handle), ctypes.byref(attr), 1
                )
                if rv_local != CKR_OK:
                    print(f'Ошибка получения атрибута: 0x{rv_local:08X}', file=sys.stderr)
                    return None
                if attr.ulValueLen == 0:
                    return None
                buf = (ctypes.c_ubyte * attr.ulValueLen)()
                attr.pValue = ctypes.cast(buf, ctypes.c_void_p)
                rv_local = pkcs11.C_GetAttributeValue(
                    session, ctypes.c_ulong(handle), ctypes.byref(attr), 1
                )
                if rv_local != CKR_OK:
                    print(f'Ошибка получения атрибута: 0x{rv_local:08X}', file=sys.stderr)
                    return None
                return bytes(buf)

            pairs = []

            def add_handle(kind, handle):
                key_id = get_id(handle)
                for entry in pairs:
                    if entry['key_id'] == key_id and kind not in entry:
                        entry[kind] = handle
                        return
                pairs.append({'key_id': key_id, kind: handle})

            for h in search_objects(CKO_PUBLIC_KEY):
                add_handle('public', h)

            for h in search_objects(CKO_PRIVATE_KEY):
                add_handle('private', h)

            sorted_pairs = sorted(
                enumerate(pairs),
                key=lambda item: ((item[1]['key_id'] or b''), item[0]),
            )

            if key_number < 1 or key_number > len(sorted_pairs):
                print('Ключ с таким номером не найден')
            else:
                pair = sorted_pairs[key_number - 1][1]
                handles_to_delete = []
                if 'private' in pair:
                    handles_to_delete.append(pair['private'])
                if 'public' in pair:
                    handles_to_delete.append(pair['public'])
                for handle_value in handles_to_delete:
                    rv_local = pkcs11.C_DestroyObject(
                        session, ctypes.c_ulong(handle_value)
                    )
                    if rv_local not in (CKR_OK, CKR_OBJECT_HANDLE_INVALID):
                        print(f'Ошибка удаления объекта: 0x{rv_local:08X}')
    finally:
        if logged_in:
            pkcs11.C_Logout(session)
        if session_opened:
            pkcs11.C_CloseSession(session)
        if initialized:
            pkcs11.C_Finalize(None)
