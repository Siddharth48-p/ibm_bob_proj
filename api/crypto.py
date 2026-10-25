"""Authenticated encryption for contact, location, and provider-token fields."""
import base64
import ctypes
import os
from ctypes import wintypes

from . import settings


_DPAPI_PREFIX = "dpapi:v1:"


class _DataBlob(ctypes.Structure):
    _fields_ = [("cbData", wintypes.DWORD), ("pbData", ctypes.POINTER(ctypes.c_ubyte))]


def _windows_protect(value: bytes, decrypt: bool = False) -> bytes:
    """Use the signed-in Windows user's DPAPI for local development fallback."""
    if os.name != "nt" or settings.APP_ENV == "production":
        raise RuntimeError("Install cryptography and configure a Fernet key for encrypted fields.")
    crypt32 = ctypes.WinDLL("crypt32", use_last_error=True)
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    data_buffer = ctypes.create_string_buffer(value)
    source = _DataBlob(len(value), ctypes.cast(data_buffer, ctypes.POINTER(ctypes.c_ubyte)))
    result = _DataBlob()
    flags = 0x1  # CRYPTPROTECT_UI_FORBIDDEN
    if decrypt:
        description = wintypes.LPWSTR()
        crypt32.CryptUnprotectData.argtypes = [ctypes.POINTER(_DataBlob), ctypes.POINTER(wintypes.LPWSTR), ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p, wintypes.DWORD, ctypes.POINTER(_DataBlob)]
        crypt32.CryptUnprotectData.restype = wintypes.BOOL
        ok = crypt32.CryptUnprotectData(ctypes.byref(source), ctypes.byref(description), None, None, None, flags, ctypes.byref(result))
    else:
        crypt32.CryptProtectData.argtypes = [ctypes.POINTER(_DataBlob), wintypes.LPCWSTR, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p, wintypes.DWORD, ctypes.POINTER(_DataBlob)]
        crypt32.CryptProtectData.restype = wintypes.BOOL
        ok = crypt32.CryptProtectData(ctypes.byref(source), "CareCircle local development data", None, None, None, flags, ctypes.byref(result))
    if not ok:
        raise ctypes.WinError(ctypes.get_last_error())
    try:
        return bytes(result.pbData[:result.cbData])
    finally:
        kernel32.LocalFree.argtypes = [ctypes.c_void_p]
        kernel32.LocalFree.restype = ctypes.c_void_p
        kernel32.LocalFree(result.pbData)


def _fernet_or_none(key: str):
    if not key:
        return None
    try:
        from cryptography.fernet import Fernet
    except ImportError:
        if os.name == "nt" and settings.APP_ENV != "production":
            return None
        raise RuntimeError("Install the cryptography dependency to use encrypted fields.")
    return Fernet(key.encode())


def encrypt(value: str | None) -> str | None:
    if value is None or value == "":
        return value
    fernet = _fernet_or_none(settings.DATA_ENCRYPTION_KEY)
    if fernet:
        return fernet.encrypt(value.encode()).decode()
    return _DPAPI_PREFIX + base64.urlsafe_b64encode(_windows_protect(value.encode())).decode()


def decrypt(value: str | None) -> str | None:
    if value is None or value == "":
        return value
    if value.startswith(_DPAPI_PREFIX):
        encrypted = base64.urlsafe_b64decode(value[len(_DPAPI_PREFIX):].encode())
        return _windows_protect(encrypted, decrypt=True).decode()
    fernet = _fernet_or_none(settings.DATA_ENCRYPTION_KEY)
    if not fernet:
        raise RuntimeError("DATA_ENCRYPTION_KEY is required to decrypt this profile field.")
    return fernet.decrypt(value.encode()).decode()


def encrypt_token(value: str) -> str:
    fernet = _fernet_or_none(settings.TOKEN_ENCRYPTION_KEY)
    if fernet:
        return fernet.encrypt(value.encode()).decode()
    return _DPAPI_PREFIX + base64.urlsafe_b64encode(_windows_protect(value.encode())).decode()


def decrypt_token(value: str) -> str:
    if value.startswith(_DPAPI_PREFIX):
        encrypted = base64.urlsafe_b64decode(value[len(_DPAPI_PREFIX):].encode())
        return _windows_protect(encrypted, decrypt=True).decode()
    fernet = _fernet_or_none(settings.TOKEN_ENCRYPTION_KEY)
    if not fernet:
        raise RuntimeError("TOKEN_ENCRYPTION_KEY is required to decrypt provider tokens.")
    return fernet.decrypt(value.encode()).decode()
