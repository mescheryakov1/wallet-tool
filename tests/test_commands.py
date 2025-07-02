import ctypes
from types import SimpleNamespace
import os
import sys
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
import commands
import pkcs11
import pkcs11_structs as structs


def test_list_objects_search_template(monkeypatch):
    pkcs11_mock = SimpleNamespace()

    def open_session(slot, flags, app, notify, session_ptr):
        session_ptr._obj.value = 123
        return 0
    pkcs11_mock.C_OpenSession = open_session

    pkcs11_mock.C_Login = lambda *args: 0
    captured = {}

    def find_objects_init(session_handle, template_ptr, count):
        arr_type = structs.CK_ATTRIBUTE * count
        arr = ctypes.cast(template_ptr, ctypes.POINTER(arr_type)).contents
        attr = arr[0]
        captured['session'] = session_handle
        captured['type'] = attr.type
        val_ptr = ctypes.cast(attr.pValue, ctypes.POINTER(ctypes.c_ulong))
        captured['value'] = val_ptr.contents.value
        captured['len'] = attr.ulValueLen
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

    commands.list_objects(slot_id=1, pin="0000")

    assert captured['session'] == 123
    assert captured['type'] == structs.CKA_CLASS
    assert captured['value'] == structs.CKO_PUBLIC_KEY
    assert captured['len'] == ctypes.sizeof(ctypes.c_ulong)
