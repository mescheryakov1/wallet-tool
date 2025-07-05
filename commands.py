import ctypes
import sys
from pkcs11 import pkcs11_command
from ecdsa import SECP256k1, SigningKey
from ed25519 import create_keypair
from pkcs11_structs import (
    CK_INFO,
    CK_TOKEN_INFO,
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
        return decoded

    raise ValueError(f"Unknown mode {mode}")

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
    pin_bytes = pin.encode('utf-8') if pin else None
    label = label.encode('utf-8')

    if pin_bytes is None:
        print('Необходимо указать PIN-код для фабричного сброса.', file=sys.stderr)
        return

    rv = pkcs11.C_EX_InitToken(slot_id, pin_bytes, label)
    if rv == CKR_TOKEN_NOT_PRESENT:
        print('Нет подключенного кошелька, подключите кошелек')
    elif rv != 0:
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
def list_objects(pkcs11, slot_id, pin):
    """Выводит список ключей. Если PIN не задан, показываются только публичные ключи."""
    define_pkcs11_functions(pkcs11)

    session = ctypes.c_ulong()
    rv = pkcs11.C_OpenSession(slot_id, CKF_SERIAL_SESSION | CKF_RW_SESSION, None, None, ctypes.byref(session))
    if rv == CKR_TOKEN_NOT_PRESENT:
        print('Нет подключенного кошелька, подключите кошелек')
        return
    if rv != 0:
        print(f'C_OpenSession вернула ошибку: 0x{rv:08X}')
        return

    logged_in = False
    if pin:
        rv = pkcs11.C_Login(session, 1, pin.encode('utf-8'), len(pin))
        if rv != 0:
            print(f'C_Login вернула ошибку: 0x{rv:08X}')
            pkcs11.C_CloseSession(session)
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

        rv = pkcs11.C_FindObjectsInit(session.value, template, 1)
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
            rv = pkcs11.C_GetAttributeValue(session, ctypes.c_ulong(handle), ctypes.byref(attr_template), 1)
            if rv != 0 or attr_template.ulValueLen == 0:
                continue
            buf = (ctypes.c_ubyte * attr_template.ulValueLen)()
            attr_template.pValue = ctypes.cast(buf, ctypes.c_void_p)
            rv = pkcs11.C_GetAttributeValue(session, ctypes.c_ulong(handle), ctypes.byref(attr_template), 1)
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

    print('Список ключей в кошельке:')
    for idx, key_id in enumerate(sorted(objects.keys(), key=lambda x: x or b''), start=1):
        pair = objects[key_id]
        key_type = None
        if 'public' in pair and 'CKA_KEY_TYPE' in pair['public'][1]:
            key_type = pair['public'][1]['CKA_KEY_TYPE']
        elif 'private' in pair and 'CKA_KEY_TYPE' in pair['private'][1]:
            key_type = pair['private'][1]['CKA_KEY_TYPE']
        suffix = f" ({key_type_description.get(key_type)})" if key_type in key_type_description else ''
        print(f'  Ключ \N{numero sign}{idx}{suffix}:')
        if 'public' in pair:
            h, attrs = pair['public']
            print('    Публичный ключ')
            for name in ['CKA_LABEL', 'CKA_ID', 'CKA_VALUE']:
                raw = attrs.get(name)
                if raw is None and name == 'CKA_LABEL' and 'private' in pair:
                    raw = pair['private'][1].get(name)
                if raw is not None:
                    hex_repr = format_attribute_value(raw, "hex")
                    text_repr = format_attribute_value(raw, "text")
                    print(f'      {name} (HEX): {hex_repr}')
                    print(f'      {name} (TEXT): {text_repr}')
        if 'private' in pair:
            h, attrs = pair['private']
            print('    Закрытый ключ')
            for name in ['CKA_LABEL', 'CKA_ID', 'CKA_VALUE']:
                if name in attrs:
                    raw = attrs[name]
                    hex_repr = format_attribute_value(raw, "hex")
                    text_repr = format_attribute_value(raw, "text")
                    print(f'      {name} (HEX): {hex_repr}')
                    print(f'      {name} (TEXT): {text_repr}')

    pkcs11.C_CloseSession(session)


def generate_key(key_type: str):
    """Generate key pair of specified type and print it in HEX."""

    if key_type == "secp256k1":
        sk = SigningKey.generate(curve=SECP256k1)
        vk = sk.get_verifying_key()
        print("Закрытый ключ (HEX):", sk.to_string().hex())
        print("Публичный ключ (HEX):", vk.to_string().hex())
    elif key_type == "ed25519":
        sk, vk = create_keypair()
        print("Закрытый ключ (HEX):", sk.to_seed().hex())
        print("Публичный ключ (HEX):", vk.to_bytes().hex())
    else:
        print("Неизвестный тип ключа:", key_type)
