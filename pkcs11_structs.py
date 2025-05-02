import ctypes
from pkcs11 import CK_INFO

# Константы
CKA_CLASS = 0x00000000  # Тип объекта
CKO_CERTIFICATE = 0x00000001  # Объект сертификата
CKF_SERIAL_SESSION = 1 << 1  # 0x00000002
CKF_RW_SESSION = 1 << 2  # 0x00000004

# Структуры PKCS#11

class CK_SLOT_INFO(ctypes.Structure):
    _fields_ = [
        ('slotDescription', ctypes.c_char * 64),
        ('manufacturerID', ctypes.c_char * 32),
        ('flags', ctypes.c_ulong),
        ('hardwareVersion', CK_INFO),
        ('firmwareVersion', CK_INFO),
    ]

class CK_TOKEN_INFO(ctypes.Structure):
    _fields_ = [
        ('label', ctypes.c_char * 32),
        ('manufacturerID', ctypes.c_char * 32),
        ('model', ctypes.c_char * 16),
        ('serialNumber', ctypes.c_char * 16),
        ('flags', ctypes.c_ulong),
        ('ulMaxSessionCount', ctypes.c_ulong),
        ('ulSessionCount', ctypes.c_ulong),
        ('ulMaxRwSessionCount', ctypes.c_ulong),
        ('ulRwSessionCount', ctypes.c_ulong),
        ('ulMaxPinLen', ctypes.c_ulong),
        ('ulMinPinLen', ctypes.c_ulong),
        ('ulTotalPublicMemory', ctypes.c_ulong),
        ('ulFreePublicMemory', ctypes.c_ulong),
        ('ulTotalPrivateMemory', ctypes.c_ulong),
        ('ulFreePrivateMemory', ctypes.c_ulong),
        ('hardwareVersion', CK_INFO),
        ('firmwareVersion', CK_INFO),
        ('utcTime', ctypes.c_char * 16),
    ]

class CK_ATTRIBUTE(ctypes.Structure):
    _fields_ = [
        ('type', ctypes.c_ulong),
        ('pValue', ctypes.c_void_p),
        ('ulValueLen', ctypes.c_ulong),
    ]
