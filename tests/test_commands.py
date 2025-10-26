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

    login_args = []
    def login(*args):
        login_args.append(args)
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
    logout_called = []
    pkcs11_mock.C_Logout = lambda session: logout_called.append(True) or 0

    monkeypatch.setattr(pkcs11, "load_pkcs11_lib", lambda: pkcs11_mock)
    monkeypatch.setattr(pkcs11, "initialize_library", lambda x: None)
    monkeypatch.setattr(pkcs11, "finalize_library", lambda x: None)
    monkeypatch.setattr(commands, "define_pkcs11_functions", lambda x: None)

    commands.list_objects(slot_id=1, pin=None)

    out = capsys.readouterr().out
    assert "Закрытые ключи не отображаются" in out
    assert login_args == []
    assert captured == [structs.CKO_PUBLIC_KEY]
    assert logout_called == []


def test_library_info_prints_wallet_description(monkeypatch, capsys):
    pkcs11_mock = SimpleNamespace()
    expected_desc = "Rutoken Wallet PKCS #11 library"

    def get_info(info_ptr):
        info = ctypes.cast(info_ptr, ctypes.POINTER(structs.CK_INFO)).contents
        info.cryptokiVersion.major = 2
        info.cryptokiVersion.minor = 40
        info.libraryVersion.major = 3
        info.libraryVersion.minor = 20
        info.manufacturerID = b"Aktiv".ljust(len(info.manufacturerID), b"\0")
        info.libraryDescription = expected_desc.encode("utf-8").ljust(
            len(info.libraryDescription),
            b"\0",
        )
        return 0

    pkcs11_mock.C_GetInfo = get_info

    monkeypatch.setattr(pkcs11, "load_pkcs11_lib", lambda: pkcs11_mock)
    monkeypatch.setattr(pkcs11, "initialize_library", lambda x: None)
    monkeypatch.setattr(pkcs11, "finalize_library", lambda x: None)
    monkeypatch.setattr(commands, "define_pkcs11_functions", lambda x: None)

    commands.library_info()

    out = capsys.readouterr().out
    assert expected_desc in out


def test_list_objects_with_pin_search_templates(monkeypatch):
    pkcs11_mock = SimpleNamespace()

    def open_session(slot, flags, app, notify, session_ptr):
        session_ptr._obj.value = 123
        return 0
    pkcs11_mock.C_OpenSession = open_session

    pkcs11_mock.C_FindObjectsFinal = lambda session: 0
    pkcs11_mock.C_CloseSession = lambda session: 0
    pkcs11_mock.C_GetAttributeValue = lambda *args: 0
    logout_called = []
    pkcs11_mock.C_Logout = lambda session: logout_called.append(True) or 0

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

    login_args = []
    def login(*args):
        login_args.append(args)
        return 0
    pkcs11_mock.C_Login = login

    monkeypatch.setattr(pkcs11, "load_pkcs11_lib", lambda: pkcs11_mock)
    monkeypatch.setattr(pkcs11, "initialize_library", lambda x: None)
    monkeypatch.setattr(pkcs11, "finalize_library", lambda x: None)
    monkeypatch.setattr(commands, "define_pkcs11_functions", lambda x: None)

    commands.list_objects(slot_id=1, pin="0000")

    assert len(login_args) == 1
    assert login_args[0][1] == structs.CKU_USER
    assert set(calls) == {structs.CKO_PUBLIC_KEY, structs.CKO_PRIVATE_KEY}
    assert logout_called == [True]


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


def test_format_attribute_value_text_truncate():
    data = b"a" * 40
    out = commands.format_attribute_value(data, "text")
    assert out == "a" * 30 + "..."


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
    logout_called = []
    pkcs11_mock.C_Logout = lambda session: logout_called.append(True) or 0

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


def test_public_key_label_from_private(monkeypatch, capsys):
    """Public key should display label taken from the corresponding private key."""
    pkcs11_mock = SimpleNamespace()

    def open_session(slot, flags, app, notify, session_ptr):
        session_ptr._obj.value = 1
        return 0

    pkcs11_mock.C_OpenSession = open_session

    current_class = None

    def find_objects_init(session_handle, template_ptr, count):
        arr_type = structs.CK_ATTRIBUTE * count
        arr = ctypes.cast(template_ptr, ctypes.POINTER(arr_type)).contents
        attr = arr[0]
        val_ptr = ctypes.cast(attr.pValue, ctypes.POINTER(ctypes.c_ulong))
        nonlocal current_class
        current_class = val_ptr.contents.value
        return 0

    pkcs11_mock.C_FindObjectsInit = find_objects_init

    def find_objects(session, obj_ptr, max_obj, count_ptr):
        if current_class == structs.CKO_PUBLIC_KEY and not hasattr(find_objects, "pub_done"):
            obj_ptr._obj.value = 10
            count_ptr._obj.value = 1
            find_objects.pub_done = True
        elif current_class == structs.CKO_PRIVATE_KEY and not hasattr(find_objects, "priv_done"):
            obj_ptr._obj.value = 11
            count_ptr._obj.value = 1
            find_objects.priv_done = True
        else:
            count_ptr._obj.value = 0
        return 0

    pkcs11_mock.C_FindObjects = find_objects
    pkcs11_mock.C_FindObjectsFinal = lambda session: 0
    pkcs11_mock.C_CloseSession = lambda session: 0
    logout_called = []
    pkcs11_mock.C_Logout = lambda session: logout_called.append(True) or 0

    LABEL = b"my label"

    def get_attribute_value(session, obj, attr_ptr, count):
        attr = ctypes.cast(attr_ptr, ctypes.POINTER(structs.CK_ATTRIBUTE)).contents
        handle = obj if isinstance(obj, int) else obj.value
        if not attr.pValue:
            if attr.type == structs.CKA_KEY_TYPE:
                attr.ulValueLen = ctypes.sizeof(ctypes.c_ulong)
            elif attr.type == structs.CKA_LABEL and handle == 11:
                attr.ulValueLen = len(LABEL)
            else:
                attr.ulValueLen = 0
            return 0
        if attr.type == structs.CKA_KEY_TYPE:
            val = ctypes.c_ulong(structs.CKK_RSA)
            ctypes.memmove(attr.pValue, ctypes.byref(val), ctypes.sizeof(val))
        elif attr.type == structs.CKA_LABEL and handle == 11:
            ctypes.memmove(attr.pValue, LABEL, len(LABEL))
        return 0

    pkcs11_mock.C_GetAttributeValue = get_attribute_value
    login_args = []
    def login(*args, **kwargs):
        login_args.append(args)
        return 0
    pkcs11_mock.C_Login = login

    monkeypatch.setattr(pkcs11, "load_pkcs11_lib", lambda: pkcs11_mock)
    monkeypatch.setattr(pkcs11, "initialize_library", lambda x: None)
    monkeypatch.setattr(pkcs11, "finalize_library", lambda x: None)
    monkeypatch.setattr(commands, "define_pkcs11_functions", lambda x: None)

    commands.list_objects(slot_id=1, pin="0000")

    out = capsys.readouterr().out.splitlines()
    pub_index = out.index("    \u041f\u0443\u0431\u043b\u0438\u0447\u043d\u044b\u0439 \u043a\u043b\u044e\u0447")
    assert any("CKA_LABEL" in line for line in out[pub_index:pub_index + 5])
    assert login_args[0][1] == structs.CKU_USER
    assert logout_called == [True]
