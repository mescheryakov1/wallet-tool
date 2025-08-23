import ctypes
from types import SimpleNamespace
import os, sys
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
import commands
import pkcs11
import pkcs11_structs as structs


def setup_mock(monkeypatch, with_private):
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

    def find_objects_init(session_handle, template_ptr, count):
        arr_type = structs.CK_ATTRIBUTE * count
        arr = ctypes.cast(template_ptr, ctypes.POINTER(arr_type)).contents
        val_ptr = ctypes.cast(arr[0].pValue, ctypes.POINTER(ctypes.c_ulong))
        nonlocal current_class
        current_class = val_ptr.contents.value
        return 0
    pkcs11_mock.C_FindObjectsInit = find_objects_init

    def find_objects(session, obj_ptr, max_obj, count_ptr):
        if current_class == structs.CKO_PUBLIC_KEY and not hasattr(find_objects, 'pub_done'):
            obj_ptr._obj.value = 10
            count_ptr._obj.value = 1
            find_objects.pub_done = True
        elif with_private and current_class == structs.CKO_PRIVATE_KEY and not hasattr(find_objects, 'priv_done'):
            obj_ptr._obj.value = 11
            count_ptr._obj.value = 1
            find_objects.priv_done = True
        else:
            count_ptr._obj.value = 0
        return 0
    pkcs11_mock.C_FindObjects = find_objects

    def get_attribute_value(session, obj, attr_ptr, count):
        attr = ctypes.cast(attr_ptr, ctypes.POINTER(structs.CK_ATTRIBUTE)).contents
        if not attr.pValue:
            if attr.type == structs.CKA_ID:
                attr.ulValueLen = 1
            else:
                attr.ulValueLen = 0
            return 0
        if attr.type == structs.CKA_ID:
            b = (ctypes.c_ubyte * 1)(1)
            ctypes.memmove(attr.pValue, b, 1)
        return 0
    pkcs11_mock.C_GetAttributeValue = get_attribute_value

    destroyed = []

    def destroy_object(session, handle):
        destroyed.append(handle)
        return 0
    pkcs11_mock.C_DestroyObject = destroy_object

    monkeypatch.setattr(pkcs11, 'load_pkcs11_lib', lambda: pkcs11_mock)
    monkeypatch.setattr(pkcs11, 'initialize_library', lambda x: None)
    monkeypatch.setattr(pkcs11, 'finalize_library', lambda x: None)
    monkeypatch.setattr(commands, 'define_pkcs11_functions', lambda x: None)

    return destroyed, login_args, logout_called


def test_delete_pair_with_private(monkeypatch):
    destroyed, login_args, logout_called = setup_mock(monkeypatch, True)

    commands.delete_key_pair(slot_id=1, pin='0000', number=1)

    assert set(destroyed) == {10, 11}
    assert login_args[0][1] == structs.CKU_USER
    assert logout_called == [True]


def test_delete_pair_requires_pin(monkeypatch, capsys):
    destroyed, login_args, logout_called = setup_mock(monkeypatch, False)

    commands.delete_key_pair(slot_id=1, pin=None, number=1)

    err = capsys.readouterr().err
    assert 'PIN-код' in err
    assert destroyed == []
    assert login_args == []
    assert logout_called == [True]
