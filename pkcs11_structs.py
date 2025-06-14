import ctypes

# Константы
CKA_CLASS = 0x00000000  # Тип объекта
CKO_CERTIFICATE = 0x00000001  # Объект сертификата
CKO_PRIVATE_KEY = 0x00000002  # Объект закрытого ключа
CKO_PUBLIC_KEY = 0x00000003  # Объект открытого ключа
CKO_SECRET_KEY = 0x00000004  # Объект секретного ключа
CKO_DATA = 0x00000005  # Объект данных
CKO_DOMAIN_PARAMETERS = 0x00000006  # Объект параметров домена
CKO_HW_FEATURE = 0x00000007  # Объект аппаратного обеспечения

CKF_SERIAL_SESSION = 1 << 1  # 0x00000002
CKF_RW_SESSION = 1 << 2  # 0x00000004

# Структуры PKCS#11

CK_VOID_PTR = ctypes.c_void_p

class CK_VERSION(ctypes.Structure):
    _fields_ = [('major', ctypes.c_ubyte), ('minor', ctypes.c_ubyte)]

class CK_INFO(ctypes.Structure):
    _fields_ = [
        ('cryptokiVersion', CK_VERSION),
        ('manufacturerID', ctypes.c_char * 32),
        ('flags', ctypes.c_ulong),
        ('libraryDescription', ctypes.c_char * 32),
        ('libraryVersion', CK_VERSION),
    ]

class CK_SLOT_INFO(ctypes.Structure):
    _fields_ = [
        ('slotDescription', ctypes.c_char * 64),
        ('manufacturerID', ctypes.c_char * 32),
        ('flags', ctypes.c_ulong),
        ('hardwareVersion', CK_VERSION),
        ('firmwareVersion', CK_VERSION),
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
        ('hardwareVersion', CK_VERSION),
        ('firmwareVersion', CK_VERSION),
        ('utcTime', ctypes.c_char * 16),
    ]

class CK_ATTRIBUTE(ctypes.Structure):
    _fields_ = [
        ('type', ctypes.c_ulong),
        ('pValue', ctypes.c_void_p),
        ('ulValueLen', ctypes.c_ulong),
    ]
