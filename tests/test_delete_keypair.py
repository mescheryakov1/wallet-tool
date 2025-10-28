import ctypes
from types import SimpleNamespace
import os, sys
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
import commands
import pkcs11
import pkcs11_structs as structs


def setup_mock(monkeypatch, public_handles, private_handles=None, ids=None):
    pkcs11_mock = SimpleNamespace()

    def open_session(slot, flags, app, notify, session_ptr):
        session_ptr._obj.value = 1
        return 0
    pkcs11_mock.C_OpenSession = open_session
    login_args = []
    def login(*args, **kwargs):
        login_args.append(args)
        return 0
    pkcs11_mock.C_Login = login
    pkcs11_mock.C_FindObjectsFinal = lambda session: 0
    pkcs11_mock.C_CloseSession = lambda session: 0
    logout_called = []
    pkcs11_mock.C_Logout = lambda session: logout_called.append(True) or 0

    current_class = None
    public_handles = list(public_handles)
    private_handles = list(private_handles or [])
    ids = ids if ids is not None else {
        handle: b"\x01" for handle in [*public_handles, *private_handles]
    }
    pub_index = 0
    priv_index = 0

    def find_objects_init(session_handle, template_ptr, count):
        arr_type = structs.CK_ATTRIBUTE * count
        arr = ctypes.cast(template_ptr, ctypes.POINTER(arr_type)).contents
        val_ptr = ctypes.cast(arr[0].pValue, ctypes.POINTER(ctypes.c_ulong))
        nonlocal current_class
        current_class = val_ptr.contents.value
        return 0
    pkcs11_mock.C_FindObjectsInit = find_objects_init
    def find_objects(session, obj_ptr, max_obj, count_ptr):
        nonlocal pub_index, priv_index
        if current_class == structs.CKO_PUBLIC_KEY:
            if pub_index < len(public_handles):
                obj_ptr._obj.value = public_handles[pub_index]
                count_ptr._obj.value = 1
                pub_index += 1
            else:
                count_ptr._obj.value = 0
        elif current_class == structs.CKO_PRIVATE_KEY:
            if priv_index < len(private_handles):
                obj_ptr._obj.value = private_handles[priv_index]
                count_ptr._obj.value = 1
                priv_index += 1
            else:
                count_ptr._obj.value = 0
        else:
            count_ptr._obj.value = 0
        return 0
    pkcs11_mock.C_FindObjects = find_objects

    def get_attribute_value(session, obj, attr_ptr, count):
        attr = ctypes.cast(attr_ptr, ctypes.POINTER(structs.CK_ATTRIBUTE)).contents
        if attr.type == structs.CKA_ID:
            handle = obj.value
            value = ids.get(handle)
            if not attr.pValue:
                attr.ulValueLen = len(value) if value is not None else 0
                return 0
            if value is not None:
                buf = (ctypes.c_ubyte * len(value)).from_buffer_copy(value)
                ctypes.memmove(attr.pValue, buf, len(value))
            return 0
        attr.ulValueLen = 0
        return 0
    pkcs11_mock.C_GetAttributeValue = get_attribute_value

    destroyed = []

    def destroy_object(session, handle):
        destroyed.append(getattr(handle, 'value', handle))
        return 0
    pkcs11_mock.C_DestroyObject = destroy_object

    monkeypatch.setattr(pkcs11, 'load_pkcs11_lib', lambda: pkcs11_mock)
    monkeypatch.setattr(pkcs11, 'initialize_library', lambda x: None)
    monkeypatch.setattr(pkcs11, 'finalize_library', lambda x: None)
    monkeypatch.setattr(commands, 'define_pkcs11_functions', lambda x: None)

    return destroyed, login_args, logout_called


def test_delete_pair_with_private(monkeypatch):
    destroyed, login_args, logout_called = setup_mock(
        monkeypatch,
        public_handles=[10],
        private_handles=[11],
    )

    commands.delete_key_pair(wallet_id=1, pin='0000', key_number=1)

    assert set(destroyed) == {10, 11}
    assert login_args[0][1] == structs.CKU_USER
    assert logout_called == [True]


def test_delete_pair_requires_pin(monkeypatch, capsys):
    destroyed, login_args, logout_called = setup_mock(
        monkeypatch,
        public_handles=[10],
        private_handles=[],
    )

    commands.delete_key_pair(wallet_id=1, pin=None, key_number=1)

    err = capsys.readouterr().err
    assert 'PIN-код' in err
    assert destroyed == []
    assert login_args == []
    assert logout_called == []


def test_delete_pair_requires_key_number(monkeypatch, capsys):
    destroyed, login_args, logout_called = setup_mock(
        monkeypatch,
        public_handles=[10],
        private_handles=[],
    )

    commands.delete_key_pair(wallet_id=1, pin='0000')

    err = capsys.readouterr().err
    assert '--key-number' in err
    assert destroyed == []
    assert login_args == []
    # Logout is not called when пользователь не вводил PIN
    assert logout_called == []


def test_delete_pair_with_same_id_enumeration(monkeypatch):
    destroyed, login_args, logout_called = setup_mock(
        monkeypatch,
        public_handles=[10, 20, 30],
        private_handles=[11, 21, 31],
        ids={
            10: None,
            11: None,
            20: None,
            21: None,
            30: None,
            31: None,
        },
    )

    commands.delete_key_pair(wallet_id=1, pin='0000', key_number=2)

    assert destroyed == [21, 20]
    assert logout_called == [True]
