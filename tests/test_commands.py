import ctypes
from types import SimpleNamespace
import os
import sys
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
import commands
import pkcs11
import pkcs11_structs as structs


def test_list_objects_public_only_no_pin(monkeypatch, capsys):
    pkcs11_mock = SimpleNamespace()

    def open_session(slot, flags, app, notify, session_ptr):
        session_ptr._obj.value = 123
        return 0
    pkcs11_mock.C_OpenSession = open_session

    login_called = []
    def login(*args):
        login_called.append(True)
        return 0
    pkcs11_mock.C_Login = login

    captured = []

    def find_objects_init(session_handle, template_ptr, count):
        arr_type = structs.CK_ATTRIBUTE * count
        arr = ctypes.cast(template_ptr, ctypes.POINTER(arr_type)).contents
        attr = arr[0]
        val_ptr = ctypes.cast(attr.pValue, ctypes.POINTER(ctypes.c_ulong))
        captured.append(val_ptr.contents.value)
        return 0
    pkcs11_mock.C_FindObjectsInit = find_objects_init

    def find_objects(session, obj_ptr, max_obj, count_ptr):
        count_ptr._obj.value = 0
        return 0
    pkcs11_mock.C_FindObjects = find_objects

    pkcs11_mock.C_FindObjectsFinal = lambda session: 0
    pkcs11_mock.C_CloseSession = lambda session: 0
    pkcs11_mock.C_GetAttributeValue = lambda *args: 0

    monkeypatch.setattr(pkcs11, "load_pkcs11_lib", lambda: pkcs11_mock)
    monkeypatch.setattr(pkcs11, "initialize_library", lambda x: None)
    monkeypatch.setattr(pkcs11, "finalize_library", lambda x: None)
    monkeypatch.setattr(commands, "define_pkcs11_functions", lambda x: None)

    commands.list_objects(slot_id=1, pin=None)

    out = capsys.readouterr().out
    assert "Закрытые ключи не отображаются" in out
    assert login_called == []
    assert captured == [structs.CKO_PUBLIC_KEY]


def test_list_objects_with_pin_search_templates(monkeypatch):
    pkcs11_mock = SimpleNamespace()

    def open_session(slot, flags, app, notify, session_ptr):
        session_ptr._obj.value = 123
        return 0
    pkcs11_mock.C_OpenSession = open_session

    pkcs11_mock.C_FindObjectsFinal = lambda session: 0
    pkcs11_mock.C_CloseSession = lambda session: 0
    pkcs11_mock.C_GetAttributeValue = lambda *args: 0

    calls = []
    def find_objects_init(session_handle, template_ptr, count):
        arr_type = structs.CK_ATTRIBUTE * count
        arr = ctypes.cast(template_ptr, ctypes.POINTER(arr_type)).contents
        attr = arr[0]
        val_ptr = ctypes.cast(attr.pValue, ctypes.POINTER(ctypes.c_ulong))
        calls.append(val_ptr.contents.value)
        return 0
    pkcs11_mock.C_FindObjectsInit = find_objects_init

    def find_objects(session, obj_ptr, max_obj, count_ptr):
        count_ptr._obj.value = 0
        return 0
    pkcs11_mock.C_FindObjects = find_objects

    login_called = []
    def login(*args):
        login_called.append(True)
        return 0
    pkcs11_mock.C_Login = login

    monkeypatch.setattr(pkcs11, "load_pkcs11_lib", lambda: pkcs11_mock)
    monkeypatch.setattr(pkcs11, "initialize_library", lambda x: None)
    monkeypatch.setattr(pkcs11, "finalize_library", lambda x: None)
    monkeypatch.setattr(commands, "define_pkcs11_functions", lambda x: None)

    commands.list_objects(slot_id=1, pin="0000")

    assert len(login_called) == 1
    assert set(calls) == {structs.CKO_PUBLIC_KEY, structs.CKO_PRIVATE_KEY}


def test_list_wallets_no_wallet(monkeypatch, capsys):
    pkcs11_mock = SimpleNamespace()

    def get_slot_list(token_present, slot_list, count_ptr):
        count_ptr._obj.value = 0
        return 0

    pkcs11_mock.C_GetSlotList = get_slot_list

    monkeypatch.setattr(pkcs11, "load_pkcs11_lib", lambda: pkcs11_mock)
    monkeypatch.setattr(pkcs11, "initialize_library", lambda x: None)
    monkeypatch.setattr(pkcs11, "finalize_library", lambda x: None)
    monkeypatch.setattr(commands, "define_pkcs11_functions", lambda x: None)

    commands.list_wallets()

    captured = capsys.readouterr()
    assert "Нет подключенного кошелька" in captured.out


def test_factory_reset_no_wallet(monkeypatch, capsys):
    pkcs11_mock = SimpleNamespace()
    pkcs11_mock.C_EX_InitToken = lambda *args: structs.CKR_TOKEN_NOT_PRESENT

    monkeypatch.setattr(pkcs11, "load_pkcs11_lib", lambda: pkcs11_mock)
    monkeypatch.setattr(pkcs11, "initialize_library", lambda x: None)
    monkeypatch.setattr(pkcs11, "finalize_library", lambda x: None)
    monkeypatch.setattr(commands, "define_pkcs11_functions", lambda x: None)

    commands.factory_reset(slot_id=1, pin="0000", label="")

    captured = capsys.readouterr()
    assert "Нет подключенного кошелька" in captured.out


def test_list_objects_no_wallet(monkeypatch, capsys):
    pkcs11_mock = SimpleNamespace()
    pkcs11_mock.C_OpenSession = lambda *args: structs.CKR_TOKEN_NOT_PRESENT

    monkeypatch.setattr(pkcs11, "load_pkcs11_lib", lambda: pkcs11_mock)
    monkeypatch.setattr(pkcs11, "initialize_library", lambda x: None)
    monkeypatch.setattr(pkcs11, "finalize_library", lambda x: None)
    monkeypatch.setattr(commands, "define_pkcs11_functions", lambda x: None)

    commands.list_objects(slot_id=1, pin="0000")

    captured = capsys.readouterr()
    assert "Нет подключенного кошелька" in captured.out


def test_format_attribute_value_text():
    data = b"hello"
    assert commands.format_attribute_value(data, "text") == "hello"


def test_format_attribute_value_binary_text():
    data = b"\x00\x01\x02"
    assert commands.format_attribute_value(data, "text") == "двоичные данные"


def test_format_attribute_value_hex_truncate():
    data = bytes(range(40))
    out = commands.format_attribute_value(data, "hex")
    assert out.startswith("00 01 02")
    assert out.endswith("...")


def test_list_objects_prints_key_type(monkeypatch, capsys):
    pkcs11_mock = SimpleNamespace()

    def open_session(slot, flags, app, notify, session_ptr):
        session_ptr._obj.value = 1
        return 0

    pkcs11_mock.C_OpenSession = open_session

    def find_objects_init(session_handle, template_ptr, count):
        return 0

    pkcs11_mock.C_FindObjectsInit = find_objects_init

    def find_objects(session, obj_ptr, max_obj, count_ptr):
        if not hasattr(find_objects, "done"):
            obj_ptr._obj.value = 42
            count_ptr._obj.value = 1
            find_objects.done = True
        else:
            count_ptr._obj.value = 0
        return 0

    pkcs11_mock.C_FindObjects = find_objects
    pkcs11_mock.C_FindObjectsFinal = lambda session: 0
    pkcs11_mock.C_CloseSession = lambda session: 0

    def get_attribute_value(session, obj, attr_ptr, count):
        attr = ctypes.cast(attr_ptr, ctypes.POINTER(structs.CK_ATTRIBUTE)).contents
        if not attr.pValue:
            if attr.type == structs.CKA_KEY_TYPE:
                attr.ulValueLen = ctypes.sizeof(ctypes.c_ulong)
            else:
                attr.ulValueLen = 0
            return 0
        if attr.type == structs.CKA_KEY_TYPE:
            val = ctypes.c_ulong(structs.CKK_RSA)
            ctypes.memmove(attr.pValue, ctypes.byref(val), ctypes.sizeof(val))
        return 0

    pkcs11_mock.C_GetAttributeValue = get_attribute_value

    monkeypatch.setattr(pkcs11, "load_pkcs11_lib", lambda: pkcs11_mock)
    monkeypatch.setattr(pkcs11, "initialize_library", lambda x: None)
    monkeypatch.setattr(pkcs11, "finalize_library", lambda x: None)
    monkeypatch.setattr(commands, "define_pkcs11_functions", lambda x: None)

    commands.list_objects(slot_id=1, pin=None)

    out = capsys.readouterr().out
    assert "RSA" in out


def test_list_objects_prints_ec_key_type(monkeypatch, capsys):
    """Simulate object with EC key type and expect ECDSA description."""
    pkcs11_mock = SimpleNamespace()

    def open_session(slot, flags, app, notify, session_ptr):
        session_ptr._obj.value = 1
        return 0

    pkcs11_mock.C_OpenSession = open_session
    pkcs11_mock.C_FindObjectsInit = lambda *args: 0

    def find_objects(session, obj_ptr, max_obj, count_ptr):
        if not hasattr(find_objects, "done"):
            obj_ptr._obj.value = 55
            count_ptr._obj.value = 1
            find_objects.done = True
        else:
            count_ptr._obj.value = 0
        return 0

    pkcs11_mock.C_FindObjects = find_objects
    pkcs11_mock.C_FindObjectsFinal = lambda session: 0
    pkcs11_mock.C_CloseSession = lambda session: 0

    def get_attribute_value(session, obj, attr_ptr, count):
        attr = ctypes.cast(attr_ptr, ctypes.POINTER(structs.CK_ATTRIBUTE)).contents
        if not attr.pValue:
            if attr.type == structs.CKA_KEY_TYPE:
                attr.ulValueLen = ctypes.sizeof(ctypes.c_ulong)
            else:
                attr.ulValueLen = 0
            return 0
        if attr.type == structs.CKA_KEY_TYPE:
            val = ctypes.c_ulong(structs.CKK_EC)
            ctypes.memmove(attr.pValue, ctypes.byref(val), ctypes.sizeof(val))
        return 0

    pkcs11_mock.C_GetAttributeValue = get_attribute_value

    monkeypatch.setattr(pkcs11, "load_pkcs11_lib", lambda: pkcs11_mock)
    monkeypatch.setattr(pkcs11, "initialize_library", lambda x: None)
    monkeypatch.setattr(pkcs11, "finalize_library", lambda x: None)
    monkeypatch.setattr(commands, "define_pkcs11_functions", lambda x: None)

    commands.list_objects(slot_id=1, pin=None)

    out = capsys.readouterr().out
    assert "ECDSA" in out
    assert "bitcoin" in out


def test_generate_secp256k1_length(capsys):
    commands.generate_secp256k1()
    out_lines = capsys.readouterr().out.splitlines()
    priv = out_lines[1].split(":")[1].strip()
    pub = out_lines[2].split(":")[1].strip()
    assert len(priv) == 64
    assert len(pub) == 128


def test_generate_ed25519_length(capsys):
    commands.generate_ed25519()
    out_lines = capsys.readouterr().out.splitlines()
    priv = out_lines[1].split(":")[1].strip()
    pub = out_lines[2].split(":")[1].strip()
    assert len(priv) == 64
    assert len(pub) == 64
