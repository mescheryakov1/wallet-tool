import ctypes
from pkcs11_structs import (
    CK_INFO,
    CK_SLOT_INFO,
    CK_TOKEN_INFO,
    CK_ATTRIBUTE,
    CK_TOKEN_INFO_EXTENDED,
)

def define_pkcs11_functions(pkcs11):
    """Определяет аргументы и возвращаемые значения для функций PKCS#11."""
    # C_GetInfo
    pkcs11.C_GetInfo.argtypes = [ctypes.POINTER(CK_INFO)]  # CK_INFO
    pkcs11.C_GetInfo.restype = ctypes.c_ulong

    # C_GetSlotList
    pkcs11.C_GetSlotList.argtypes = [ctypes.c_bool, ctypes.POINTER(ctypes.c_ulong), ctypes.POINTER(ctypes.c_ulong)]
    pkcs11.C_GetSlotList.restype = ctypes.c_ulong

    # C_GetTokenInfo
    pkcs11.C_GetTokenInfo.argtypes = [ctypes.c_ulong, ctypes.POINTER(CK_TOKEN_INFO)]
    pkcs11.C_GetTokenInfo.restype = ctypes.c_ulong

    # C_EX_GetTokenInfoExtended
    if hasattr(pkcs11, 'C_EX_GetTokenInfoExtended'):
        pkcs11.C_EX_GetTokenInfoExtended.argtypes = [
            ctypes.c_ulong,
            ctypes.POINTER(CK_TOKEN_INFO_EXTENDED),
        ]
        pkcs11.C_EX_GetTokenInfoExtended.restype = ctypes.c_ulong

    # C_OpenSession
    pkcs11.C_OpenSession.argtypes = [ctypes.c_ulong, ctypes.c_ulong, ctypes.c_void_p, ctypes.c_void_p, ctypes.POINTER(ctypes.c_ulong)]
    pkcs11.C_OpenSession.restype = ctypes.c_ulong

    # C_Login
    pkcs11.C_Login.argtypes = [ctypes.c_ulong, ctypes.c_ulong, ctypes.c_char_p, ctypes.c_ulong]
    pkcs11.C_Login.restype = ctypes.c_ulong

    # C_SetPIN
    pkcs11.C_SetPIN.argtypes = [
        ctypes.c_ulong,  # CK_SESSION_HANDLE
        ctypes.c_char_p,  # pOldPin
        ctypes.c_ulong,   # ulOldLen
        ctypes.c_char_p,  # pNewPin
        ctypes.c_ulong,   # ulNewLen
    ]
    pkcs11.C_SetPIN.restype = ctypes.c_ulong

    # C_FindObjectsInit
    pkcs11.C_FindObjectsInit.argtypes = [ctypes.c_ulong, ctypes.POINTER(CK_ATTRIBUTE), ctypes.c_ulong]  # CK_ATTRIBUTE
    pkcs11.C_FindObjectsInit.restype = ctypes.c_ulong

    # C_FindObjects
    pkcs11.C_FindObjects.argtypes = [ctypes.c_ulong, ctypes.POINTER(ctypes.c_ulong), ctypes.c_ulong, ctypes.POINTER(ctypes.c_ulong)]
    pkcs11.C_FindObjects.restype = ctypes.c_ulong

    # C_FindObjectsFinal
    pkcs11.C_FindObjectsFinal.argtypes = [ctypes.c_ulong]
    pkcs11.C_FindObjectsFinal.restype = ctypes.c_ulong

    # C_GetAttributeValue
    pkcs11.C_GetAttributeValue.argtypes = [
        ctypes.c_ulong,  # CK_SESSION_HANDLE
        ctypes.c_ulong,  # CK_OBJECT_HANDLE
        ctypes.POINTER(CK_ATTRIBUTE),  # CK_ATTRIBUTE_PTR
        ctypes.c_ulong,  # ulCount
    ]
    pkcs11.C_GetAttributeValue.restype = ctypes.c_ulong

    # C_SetAttributeValue
    pkcs11.C_SetAttributeValue.argtypes = [
        ctypes.c_ulong,  # CK_SESSION_HANDLE
        ctypes.c_ulong,  # CK_OBJECT_HANDLE
        ctypes.POINTER(CK_ATTRIBUTE),  # CK_ATTRIBUTE_PTR
        ctypes.c_ulong,  # ulCount
    ]
    pkcs11.C_SetAttributeValue.restype = ctypes.c_ulong

    # C_GenerateKeyPair
    from pkcs11_structs import CK_MECHANISM
    pkcs11.C_GenerateKeyPair.argtypes = [
        ctypes.c_ulong,                         # CK_SESSION_HANDLE
        ctypes.POINTER(CK_MECHANISM),           # CK_MECHANISM_PTR
        ctypes.POINTER(CK_ATTRIBUTE), ctypes.c_ulong,  # public template
        ctypes.POINTER(CK_ATTRIBUTE), ctypes.c_ulong,  # private template
        ctypes.POINTER(ctypes.c_ulong),         # CK_OBJECT_HANDLE_PTR (public)
        ctypes.POINTER(ctypes.c_ulong),         # CK_OBJECT_HANDLE_PTR (private)
    ]
    pkcs11.C_GenerateKeyPair.restype = ctypes.c_ulong

    # C_DestroyObject
    pkcs11.C_DestroyObject.argtypes = [
        ctypes.c_ulong,  # CK_SESSION_HANDLE
        ctypes.c_ulong,  # CK_OBJECT_HANDLE
    ]
    pkcs11.C_DestroyObject.restype = ctypes.c_ulong

    # C_CreateObject
    pkcs11.C_CreateObject.argtypes = [
        ctypes.c_ulong,  # CK_SESSION_HANDLE
        ctypes.POINTER(CK_ATTRIBUTE),  # CK_ATTRIBUTE_PTR
        ctypes.c_ulong,  # ulCount
        ctypes.POINTER(ctypes.c_ulong),  # CK_OBJECT_HANDLE_PTR
    ]
    pkcs11.C_CreateObject.restype = ctypes.c_ulong

    # C_CloseSession
    pkcs11.C_CloseSession.argtypes = [ctypes.c_ulong]
    pkcs11.C_CloseSession.restype = ctypes.c_ulong
