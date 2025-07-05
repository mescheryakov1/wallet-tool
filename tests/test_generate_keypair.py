import ctypes
from types import SimpleNamespace
import os
import sys
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
import commands
import pkcs11
import pkcs11_structs as structs


def make_pkcs11_mock(captured):
    pkcs11_mock = SimpleNamespace()

    def open_session(slot, flags, app, notify, session_ptr):
        session_ptr._obj.value = 1
        return 0
    pkcs11_mock.C_OpenSession = open_session
    pkcs11_mock.C_Login = lambda *args, **kwargs: 0
    pkcs11_mock.C_CloseSession = lambda session: 0

    def generate_key_pair(session, mech_ptr, pub_tpl, pub_count, priv_tpl, priv_count, pub_h_ptr, priv_h_ptr):
        mech = ctypes.cast(mech_ptr, ctypes.POINTER(structs.CK_MECHANISM)).contents
        captured['mechanism'] = mech.mechanism
        arr_type = structs.CK_ATTRIBUTE * pub_count
        arr = ctypes.cast(pub_tpl, ctypes.POINTER(arr_type)).contents
        for attr in arr:
            if attr.type == structs.CKA_MODULUS_BITS:
                val = ctypes.cast(attr.pValue, ctypes.POINTER(ctypes.c_ulong)).contents.value
                captured['modulus_bits'] = val
        return 0
    pkcs11_mock.C_GenerateKeyPair = generate_key_pair

    return pkcs11_mock


def setup(monkeypatch, captured):
    pkcs11_mock = make_pkcs11_mock(captured)
    monkeypatch.setattr(pkcs11, 'load_pkcs11_lib', lambda: pkcs11_mock)
    monkeypatch.setattr(pkcs11, 'initialize_library', lambda x: None)
    monkeypatch.setattr(pkcs11, 'finalize_library', lambda x: None)
    monkeypatch.setattr(commands, 'define_pkcs11_functions', lambda x: None)


def test_generate_rsa2048(monkeypatch):
    captured = {}
    setup(monkeypatch, captured)

    commands.generate_key_pair(slot_id=1, pin='1111', algorithm='rsa2048')

    assert captured['mechanism'] == structs.CKM_RSA_PKCS_KEY_PAIR_GEN
    assert captured['modulus_bits'] == 2048


def test_generate_ed25519(monkeypatch):
    captured = {}
    setup(monkeypatch, captured)

    commands.generate_key_pair(slot_id=1, pin='1111', algorithm='ed25519')

    assert captured['mechanism'] == structs.CKM_EC_EDWARDS_KEY_PAIR_GEN

