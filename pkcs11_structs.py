import ctypes
import sys

# Константы
# Значения классов объектов согласно спецификации PKCS#11
CKA_CLASS = 0x00000000  # Тип объекта
CKO_DATA = 0x00000000
CKO_CERTIFICATE = 0x00000001
CKO_PUBLIC_KEY = 0x00000002
CKO_PRIVATE_KEY = 0x00000003
CKO_SECRET_KEY = 0x00000004
CKO_HW_FEATURE = 0x00000005
CKO_DOMAIN_PARAMETERS = 0x00000006

# Наиболее часто используемые атрибуты
CKA_LABEL = 0x00000003
CKA_VALUE = 0x00000011
CKA_ID = 0x00000102

CKF_SERIAL_SESSION = 1 << 1  # 0x00000002
CKF_RW_SESSION = 1 << 2  # 0x00000004

# Структуры PKCS#11

CK_VOID_PTR = ctypes.c_void_p

class CK_VERSION(ctypes.Structure):
    if sys.platform.startswith("win"):
        _pack_ = 1
    _fields_ = [('major', ctypes.c_ubyte), ('minor', ctypes.c_ubyte)]

class CK_INFO(ctypes.Structure):
    if sys.platform.startswith("win"):
        _pack_ = 1
    _fields_ = [
        ('cryptokiVersion', CK_VERSION),
        ('manufacturerID', ctypes.c_char * 32),
        ('flags', ctypes.c_ulong),
        ('libraryDescription', ctypes.c_char * 32),
        ('libraryVersion', CK_VERSION),
    ]

class CK_SLOT_INFO(ctypes.Structure):
    if sys.platform.startswith("win"):
        _pack_ = 1
    _fields_ = [
        ('slotDescription', ctypes.c_char * 64),
        ('manufacturerID', ctypes.c_char * 32),
        ('flags', ctypes.c_ulong),
        ('hardwareVersion', CK_VERSION),
        ('firmwareVersion', CK_VERSION),
    ]

class CK_TOKEN_INFO(ctypes.Structure):
    if sys.platform.startswith("win"):
        _pack_ = 1
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
        ('hardwareVersion', CK_VERSION),
        ('firmwareVersion', CK_VERSION),
        ('utcTime', ctypes.c_char * 16),
    ]

class CK_ATTRIBUTE(ctypes.Structure):
    _pack_ = 1
    _fields_ = [
        ('type', ctypes.c_ulong),
        ('pValue', ctypes.c_void_p),
        ('ulValueLen', ctypes.c_ulong),
    ]
