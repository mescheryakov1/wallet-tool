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


def test_list_objects_numbering(monkeypatch, capsys):
    """Objects are numbered sequentially when printed."""
    pkcs11_mock = SimpleNamespace()

    def open_session(slot, flags, app, notify, session_ptr):
        session_ptr._obj.value = 321
        return 0

    pkcs11_mock.C_OpenSession = open_session
    pkcs11_mock.C_Login = lambda *args: 0

    search_class = None
    def find_objects_init(session, template_ptr, count):
        arr_type = structs.CK_ATTRIBUTE * count
        attr = ctypes.cast(template_ptr, ctypes.POINTER(arr_type)).contents[0]
        val_ptr = ctypes.cast(attr.pValue, ctypes.POINTER(ctypes.c_ulong))
        nonlocal search_class
        search_class = val_ptr.contents.value
        return 0

    pkcs11_mock.C_FindObjectsInit = find_objects_init

    objects_pub = [100]
    objects_priv = [200]

    def find_objects(session, obj_ptr, max_obj, count_ptr):
        lst = objects_pub if search_class == structs.CKO_PUBLIC_KEY else objects_priv
        if lst:
            obj_ptr._obj.value = lst.pop(0)
            count_ptr._obj.value = 1
        else:
            count_ptr._obj.value = 0
        return 0

    pkcs11_mock.C_FindObjects = find_objects
    pkcs11_mock.C_FindObjectsFinal = lambda *args: 0
    pkcs11_mock.C_CloseSession = lambda *args: 0

    def get_attr(session, obj, template_ptr, count):
        template_ptr._obj.ulValueLen = 0
        return 0

    pkcs11_mock.C_GetAttributeValue = get_attr

    monkeypatch.setattr(pkcs11, "load_pkcs11_lib", lambda: pkcs11_mock)
    monkeypatch.setattr(pkcs11, "initialize_library", lambda x: None)
    monkeypatch.setattr(pkcs11, "finalize_library", lambda x: None)
    monkeypatch.setattr(commands, "define_pkcs11_functions", lambda x: None)

    commands.list_objects(slot_id=1, pin="0000")

    captured = capsys.readouterr()
    assert "Ключ #1" in captured.out
    assert "Ключ #2" in captured.out


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
