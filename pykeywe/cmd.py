from datetime import datetime
from enum import IntEnum
import struct

class CmdType(IntEnum):
    DOOR_STATE = 0x02
    DOOR_UNLOCK = 0x03
    DOOR_LOCK = 0x04
    DOOR_ONETIME_PASSWORD_SET = 0x05
    DOOR_ONETIME_PASSWORD_CLEAR = 0x06
    DOOR_ONETIME_PASSWORD_CONFIRM = 0x07
    DOOR_ENTER_COUNT = 0x08
    DOOR_PASSWORD_SET = 0x09
    DOOR_ONE_TOUCH = 0x0a
    DOOR_MODE = 0x10
    SEND_DISCONNECT = 0x12
    EKEY_REGISTER = 0x20
    EKEY_VERIFY = 0x30
    EKEY_RENEWAL = 0x31
    EKEY_CLEAR = 0x32
    DOOR_BANKS_INFO_GET = 0x40
    DOOR_BANK_PASSCODE_SET = 0x41
    DOOR_BANK_PASSCODE_DEL = 0x42
    DOOR_BANK_PASSCODE_GET = 0x43
    DOOR_BANK_CARD_SET = 0x44
    DOOR_BANK_CARD_DEL = 0x45
    DOOR_DEVICE_INFO_GET = 0x46
    DOOR_DEVICE_INFO_SET = 0x47
    DOOR_DATE_TIME_SET = 0x50

def byte(c):
    return chr(c).encode('ascii')

# sta (0x02), len, cmd, param, eom (0x03)
class Cmd:
    _type = None
    _param = None

    def __init__(self, _type, _param):
        self._type = _type
        self._param = _param

    def __bytes__(self):
        pkt = b'\x00\x00' + b'\x02' + byte(len(self._param)) + byte(int(self._type)) + self._param + b'\x03'
        return pkt + b'\x00' * (16 - len(pkt))

class WelcomeCmd:
    def __bytes__(self):
        return b'Welcome' + b'\x00'*9

class DoorModeCmd(Cmd):
    def __init__(self, _param):
        super().__init__(
            CmdType.DOOR_MODE,
            _param
        )

class DisconnectCmd(Cmd):
    def __init__(self):
        super().__init__(
            CmdType.SEND_DISCONNECT,
            b'\x13'
        )

class DoorUnlockCmd(Cmd):
    def __init__(self, duration):
        super().__init__(
            CmdType.DOOR_UNLOCK,
            struct.pack('<I', duration) + b'\x08'
        )

class DoorTimeSetCmd(Cmd):
    def __init__(self):
        now = datetime.now()
        p1 = (now.year-2000) << 16 | now.month << 8 | now.day
        p2 = now.hour << 16 | now.minute << 8 | now.second

        params = struct.pack('>I', p1)[1:] + struct.pack('>I', p2)[1:] + b'\x00\x00\x00'
        super().__init__(
            CmdType.DOOR_DATE_TIME_SET,
            params
        )

class eKeyRegisterCmd(Cmd):
    def __init__(self, key):
        super().__init__(
            CmdType.EKEY_REGISTER,
            key + b'\x00\x00\x00'
        )

class eKeyVerifyCmd(Cmd):
    def __init__(self, key):
        super().__init__(
            CmdType.EKEY_VERIFY,
            key + b'\x00\x00\x00'
        )

class eKeyClearCmd(Cmd):
    def __init__(self):
        super().__init__(
            CmdType.EKEY_CLEAR,
            b'\x33'
        )

