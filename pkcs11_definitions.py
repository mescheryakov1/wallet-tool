import ctypes
from pkcs11_structs import CK_INFO, CK_SLOT_INFO, CK_TOKEN_INFO, CK_ATTRIBUTE

def define_pkcs11_functions(pkcs11):
    """Определяет аргументы и возвращаемые значения для функций PKCS#11."""
    # C_GetInfo
    pkcs11.C_GetInfo.argtypes = [ctypes.POINTER(CK_INFO)]  # CK_INFO
    pkcs11.C_GetInfo.restype = ctypes.c_ulong

    # C_EX_InitToken
    pkcs11.C_EX_InitToken.argtypes = [ctypes.c_ulong, ctypes.c_char_p, ctypes.c_char_p]
    pkcs11.C_EX_InitToken.restype = ctypes.c_ulong

    # C_GetSlotList
    pkcs11.C_GetSlotList.argtypes = [ctypes.c_bool, ctypes.POINTER(ctypes.c_ulong), ctypes.POINTER(ctypes.c_ulong)]
    pkcs11.C_GetSlotList.restype = ctypes.c_ulong

    # C_GetSlotInfo
    pkcs11.C_GetTokenInfo.argtypes = [ctypes.c_ulong, ctypes.POINTER(CK_TOKEN_INFO)]
    pkcs11.C_GetTokenInfo.restype = ctypes.c_ulong

    # C_OpenSession
    pkcs11.C_OpenSession.argtypes = [ctypes.c_ulong, ctypes.c_ulong, ctypes.c_void_p, ctypes.c_void_p, ctypes.POINTER(ctypes.c_ulong)]
    pkcs11.C_OpenSession.restype = ctypes.c_ulong

    # C_Login
    pkcs11.C_Login.argtypes = [ctypes.c_ulong, ctypes.c_ulong, ctypes.c_char_p, ctypes.c_ulong]
    pkcs11.C_Login.restype = ctypes.c_ulong

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
    pkcs11.C_GetAttributeValue.argtypes = [ctypes.c_ulong, ctypes.POINTER(CK_ATTRIBUTE), ctypes.c_ulong]  # CK_ATTRIBUTE
    pkcs11.C_GetAttributeValue.restype = ctypes.c_ulong