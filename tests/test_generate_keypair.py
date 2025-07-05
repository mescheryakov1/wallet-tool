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

        def read_attrs(ptr, count, prefix):
            arr_type = structs.CK_ATTRIBUTE * count
            arr = ctypes.cast(ptr, ctypes.POINTER(arr_type)).contents
            for attr in arr:
                if attr.type == structs.CKA_MODULUS_BITS:
                    val = ctypes.cast(attr.pValue, ctypes.POINTER(ctypes.c_ulong)).contents.value
                    captured['modulus_bits'] = val
                elif attr.type in (structs.CKA_TOKEN, structs.CKA_PRIVATE):
                    val = ctypes.cast(attr.pValue, ctypes.POINTER(ctypes.c_ubyte)).contents.value
                    captured[f'{prefix}_{attr.type}'] = val
                elif attr.type in (structs.CKA_ID, structs.CKA_LABEL,
                                   structs.CKA_GOSTR3410_PARAMS,
                                   structs.CKA_GOSTR3411_PARAMS):
                    buf = (ctypes.c_ubyte * attr.ulValueLen).from_address(attr.pValue)
                    captured[f'{prefix}_{attr.type}'] = bytes(buf)

        read_attrs(pub_tpl, pub_count, 'pub')
        read_attrs(priv_tpl, priv_count, 'priv')
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

    commands.generate_key_pair(
        slot_id=1,
        pin='1111',
        algorithm='rsa2048',
        cka_id='01',
        cka_label='lbl',
    )

    assert captured['mechanism'] == structs.CKM_RSA_PKCS_KEY_PAIR_GEN
    assert captured['modulus_bits'] == 2048
    assert captured['pub_%d' % structs.CKA_TOKEN] == 1
    assert captured['priv_%d' % structs.CKA_PRIVATE] == 1
    assert captured['pub_%d' % structs.CKA_PRIVATE] == 0
    assert captured['pub_%d' % structs.CKA_ID] == b'01'
    assert captured['priv_%d' % structs.CKA_ID] == b'01'
    assert captured['pub_%d' % structs.CKA_LABEL] == b'lbl'
    assert captured['priv_%d' % structs.CKA_LABEL] == b'lbl'


def test_generate_ed25519(monkeypatch):
    captured = {}
    setup(monkeypatch, captured)

    commands.generate_key_pair(
        slot_id=1,
        pin='1111',
        algorithm='ed25519',
        cka_id='AA',
        cka_label='x',
    )

    assert captured['mechanism'] == structs.CKM_EC_EDWARDS_KEY_PAIR_GEN
    assert captured['pub_%d' % structs.CKA_ID] == b'AA'
    assert captured['priv_%d' % structs.CKA_LABEL] == b'x'


def test_generate_missing_id_label(monkeypatch, capsys):
    captured = {}
    setup(monkeypatch, captured)

    commands.generate_key_pair(
        slot_id=1,
        pin='1111',
        algorithm='ed25519',
        cka_id='',
        cka_label='',
    )

    assert captured == {}
    err = capsys.readouterr().err
    assert 'key-id' in err and 'key-label' in err


def test_generate_gost_params(monkeypatch):
    captured = {}
    setup(monkeypatch, captured)

    commands.generate_key_pair(
        slot_id=1,
        pin='1111',
        algorithm='gost',
        cka_id='GG',
        cka_label='lbl',
    )

    assert captured['mechanism'] == structs.CKM_GOSTR3410_KEY_PAIR_GEN
    assert 'pub_%d' % structs.CKA_GOSTR3410_PARAMS in captured
    assert 'pub_%d' % structs.CKA_GOSTR3411_PARAMS in captured
    assert 'priv_%d' % structs.CKA_GOSTR3411_PARAMS in captured


