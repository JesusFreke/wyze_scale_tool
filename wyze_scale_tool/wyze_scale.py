# Copyright (c) 2024, Ben Gruver
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are met:
#
# 1. Redistributions of source code must retain the above copyright notice,
#    this list of conditions and the following disclaimer.
# 2. Redistributions in binary form must reproduce the above copyright notice,
#    this list of conditions and the following disclaimer in the documentation
#    and/or other materials provided with the distribution.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
# AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
# ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE
# LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
# CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
# SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
# INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
# CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
# ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
# POSSIBILITY OF SUCH DAMAGE.

import asyncio
import binascii
import datetime
import io
import logging
import secrets
import struct
import time
from typing import Optional, List, Sequence

import xxtea
from bleak import BleakClient, BleakGATTCharacteristic

CMD_SYNC_TIME = 0x01
CMD_USER_LIST = 0x02
CMD_CURRENT_USER = 0x03
CMD_SET_UNIT = 0x04
CMD_SET_HELLO = 0x05
CMD_RESET = 0x06
CMD_BROAD_TIME = 0x07
CMD_CUR_WEIGHT_DATA = 0x08
CMD_HISTORY_WEIGHT_DATA = 0x09
CMD_UPDATE_USER = 0x0a
CMD_DEL_USER = 0x0b
CMD_DEV_BIND_STATE = 0x0c
CMD_USER_LIST_NEW = 0x0d
CMD_CURRENT_USER_NEW = 0x0e
CMD_DEL_ALL_USER = 0x0f
CMD_HEART_MODE = 0x10
CMD_HEART_RESULT = 0x11
CMD_WEIGHT_MODE = 0x12

_LOGGER = logging.getLogger("wyze_scale")


class EncryptionReply(object):
    def __init__(self, buf):
        assert len(buf) == 12
        assert (buf[0] & 0xF0) == 0x40
        assert buf[1:4] == b'\xF0\x00\x08'
        assert buf[8:12] == b'\x00\x00\x00\x00'

        self.other_public_key = struct.unpack('<I', buf[4:8])[0]


class StatusReply(object):
    def __init__(self, buf, expected_cmd):
        assert len(buf) == 7
        assert buf[0:2] == b'\x22\x01'
        assert struct.unpack('<H', buf[2:4])[0] == 3
        assert buf[4] == expected_cmd
        assert buf[5] == 0xa8

        self.success = buf[6] == 0


class SyncTimeReply(StatusReply):
    def __init__(self, buf):
        super().__init__(buf, CMD_SYNC_TIME)


class UserListNewReply(object):
    def __init__(self, buf):
        assert (len(buf) - 7) % 25 == 0
        assert buf[0:2] == b'\x22\x01'
        assert (struct.unpack('<H', buf[2:4])[0] - 3) % 25 == 0
        assert buf[4] == CMD_USER_LIST_NEW
        assert buf[5] == 0xa8

        self.success = buf[6] == 1

        user_count = int((len(buf) - 7) / 25)

        self.users = []
        for i in range(user_count):
            buf_start = 7 + 25 * i
            buf_end = buf_start + 25
            self.users.append(UserData.parse_buffer(buf[buf_start:buf_end]))


class UpdateCurrentUserNewReply(StatusReply):
    def __init__(self, buf):
        super().__init__(buf, CMD_CURRENT_USER_NEW)


class UpdateUserReply(StatusReply):
    def __init__(self, buf):
        super().__init__(buf, CMD_UPDATE_USER)


class UpdateCurrentUserReply(StatusReply):
    def __init__(self, buf):
        super().__init__(buf, CMD_CURRENT_USER)


class DeleteUserReply(StatusReply):
    def __init__(self, buf):
        super().__init__(buf, CMD_DEL_USER)


class ResetScaleReply(StatusReply):
    def __init__(self, buf):
        super().__init__(buf, CMD_RESET)


class SetUnitReply(StatusReply):
    def __init__(self, buf):
        super().__init__(buf, CMD_SET_UNIT)


class SetHelloReply(StatusReply):
    def __init__(self, buf):
        super().__init__(buf, CMD_SET_HELLO)


class HistoricalWeightData(object):
    def __init__(self, buf):
        assert len(buf) == 53
        assert buf[0:2] == b'\x22\x01'
        assert struct.unpack('<H', buf[2:4])[0] == 49
        assert buf[4] == CMD_HISTORY_WEIGHT_DATA
        assert buf[5] == 0xa8

        self.success = buf[6] == 1

        (self.raw_timestamp,
         self.user_id,
         self.raw_sex,
         self.age,
         self.height,
         self.athlete_mode,
         self.only_weight,
         self.raw_weight,
         self.impedance,
         self.bfp,
         self.muscleMass,
         self.boneMass,
         self.water,
         self.protein,
         self.lbm,
         self.vfal,
         self.bmr,
         self.bodyAge,
         self.bmi) = struct.unpack('<I16sBBBBBHHHHBHHHBHBH', buf[7:])

        current_tz = datetime.datetime.now().astimezone().tzinfo
        self.timestamp = datetime.datetime.fromtimestamp(self.raw_timestamp, current_tz)

    @property
    def weight_kgs(self):
        return self.raw_weight / 100

    @property
    def weight_lbs(self):
        return round(self.weight_kgs * 2.20462, 2)

    @property
    def sex(self):
        if self.raw_sex == 1:
            return 'M'
        return 'F'

    def timestamp_str(self):
        return self.timestamp.strftime("%Y-%m-%d %H:%M:%S")

    def __str__(self):
        return f"timestamp={self.timestamp_str()}, " \
               f"user_id={binascii.hexlify(self.user_id)}, " \
               f"sex={self.sex}, " \
               f"age={self.age}, " \
               f"height={self.height}, " \
               f"athlete_mode={self.athlete_mode}, " \
               f"only_weight={self.only_weight}, " \
               f"weight={self.weight_kgs}kg|{self.weight_lbs}lb, " \
               f"impedance={self.impedance}, " \
               f"bfp={self.bfp}, " \
               f"muscleMass={self.muscleMass}, " \
               f"boneMass={self.boneMass}, " \
               f"water={self.water}, " \
               f"protein={self.protein}, " \
               f"lbm={self.lbm}, " \
               f"vfal={self.vfal}, " \
               f"bmr={self.bmr}, " \
               f"bodyAge={self.bodyAge}, " \
               f"bmi={self.bmi}"


class CurrentWeightData(object):
    def __init__(self, buf):
        assert len(buf) == 51
        assert buf[0:2] == b'\x22\x01'
        assert struct.unpack('<H', buf[2:4])[0] == 47
        assert buf[4] == CMD_CUR_WEIGHT_DATA
        assert buf[5] == 0xa8

        (self.battery,
         unit,
         user_id,
         raw_sex,
         age,
         height,
         athlete_mode,
         only_weight,
         self._measure_state,
         self.raw_weight,
         impedance,
         bfp,
         muscleMass,
         boneMass,
         water,
         protein,
         lbm,
         vfal,
         bmr,
         bodyAge,
         bmi) = struct.unpack('<BB16sBBBBBBHHHHBHHHBHBH', buf[6:])

    @property
    def final_measurement(self):
        # measure_state has a value of 2 once the weight has settled
        return self._measure_state == 2

    @property
    def weight_kgs(self):
        return self.raw_weight / 100

    @property
    def weight_lbs(self):
        return round(self.weight_kgs * 2.20462, 2)


REPLY_MAP = {
    CMD_SYNC_TIME: SyncTimeReply,
    CMD_USER_LIST_NEW: UserListNewReply,
    CMD_CURRENT_USER_NEW: UpdateCurrentUserNewReply,
    CMD_UPDATE_USER: UpdateUserReply,
    CMD_CURRENT_USER: UpdateCurrentUserReply,
    CMD_DEL_USER: DeleteUserReply,
    CMD_RESET: ResetScaleReply,
    CMD_SET_UNIT: SetUnitReply,
    CMD_SET_HELLO: SetHelloReply,
    CMD_CUR_WEIGHT_DATA: CurrentWeightData,
    CMD_HISTORY_WEIGHT_DATA: HistoricalWeightData
}


class UserData(object):
    def __init__(self, user_id, raw_weight, raw_sex, age, height, athlete_mode, only_weight, last_imp):
        self.user_id = user_id
        self.raw_weight = raw_weight
        self.raw_sex = raw_sex
        self.age = age
        self.height = height
        self.athlete_mode = athlete_mode
        self.only_weight = only_weight
        self.last_imp = last_imp

    @staticmethod
    def parse_buffer(buf):
        return UserData(*struct.unpack('<16sHBBBBBH', buf))

    @property
    def weight_kgs(self):
        return self.raw_weight / 100

    @property
    def weight_lbs(self):
        return round(self.weight_kgs * 2.20462, 2)

    @property
    def sex(self):
        if self.raw_sex == 1:
            return 'M'
        return 'F'

    def __str__(self):
        return f"user_id={binascii.hexlify(self.user_id)}, " \
               f"weight={self.weight_kgs}kg|{self.weight_lbs}lb, " \
               f"sex={self.sex}, " \
               f"age={self.age}, " \
               f"height={self.height}, " \
               f"athlete_mode={self.athlete_mode}, " \
               f"only_weight={self.only_weight}, " \
               f"last_imp={self.last_imp}"


class WyzeScaleProtocol(object):

    SERVICE = "0000fd7b-0000-1000-8000-00805f9b34fb"
    CHARACTERISTIC = "00000001-0000-1000-8000-00805f9b34fb"

    def __init__(self, address):
        self._address = address
        self._read_queue = None
        self._device = None
        self._characteristic = None
        self._frame = 0
        self._xxtea_key = None

    async def connect(self):
        if not self._device:
            self._device = BleakClient(self._address)

        if not self._device.is_connected:
            _LOGGER.info("Connecting")
            await self._device.connect()
            _LOGGER.info("Connected")

            self._frame = 0
            self._read_queue = asyncio.Queue()

            service = self._device.services.get_service(WyzeScaleProtocol.SERVICE)
            self._characteristic = service.get_characteristic(WyzeScaleProtocol.CHARACTERISTIC)

            await self._device.start_notify(self._characteristic, self._handle_notification)
            _LOGGER.info("Negotiating encryption")
            await self._enable_encryption()
            _LOGGER.info("Encryption negotiated")

    async def disconnect(self):
        if self._device is not None and self._device.is_connected:
            await self._device.disconnect()
            self._device = None

    def _handle_notification(self, _: BleakGATTCharacteristic, buf: bytearray):
        if (buf[0] & 0xF0) == 0x50 and buf[1] == 0x01:
            self._handle_encrypted_message(buf)
        if (buf[0] & 0xF0) == 0x40 and buf[1] == 0xF0:
            _LOGGER.debug("Received message: %s" % buf.hex())
            self._read_queue.put_nowait(EncryptionReply(buf))

    def _handle_encrypted_message(self, buf):
        assert len(buf) >= buf[3] + 4
        assert (len(buf) - 4) % 8 == 0

        payload_length = buf[3]

        message = io.BytesIO()

        for i in range(0, int(len(buf) / 8)):
            decrypted = xxtea.decrypt(buf[i * 8 + 4: (i+1) * 8 + 4], self._xxtea_key, padding=False)
            message.write(decrypted)

        decrypted_buf = message.getvalue()
        reply_class = REPLY_MAP.get(decrypted_buf[4])
        if not reply_class:
            return

        _LOGGER.debug("Received message (decrypted): %s" % bytes.hex(decrypted_buf[0:payload_length]))

        self._read_queue.put_nowait(reply_class(decrypted_buf[0:payload_length]))

    async def next_message(self, timeout_s=5):
        start_time = time.time()
        while time.time() - start_time < timeout_s:
            try:
                next_timeout = (time.time() - start_time)
                if next_timeout < 0:
                    next_timeout = 0
                message = await asyncio.wait_for(self._read_queue.get(), next_timeout)
                if message:
                    return message

            except asyncio.exceptions.TimeoutError:
                pass
        return None

    async def wait_for_message(self, reply_class, timeout_s=5):
        start_time = time.time()
        unwanted_messages = []
        try:
            while time.time() - start_time < timeout_s:
                try:
                    next_timeout = (time.time() - start_time)
                    if next_timeout < 0:
                        next_timeout = 0
                    message = await asyncio.wait_for(self._read_queue.get(), next_timeout)

                    if isinstance(message, reply_class):
                        return message
                    unwanted_messages.append(message)
                except asyncio.exceptions.TimeoutError:
                    pass
        finally:
            for unwanted_message in unwanted_messages:
                self._read_queue.put_nowait(unwanted_message)

        return None

    async def _enable_encryption(self):
        base = 5
        modulus = 0xFFFFFFC5

        private_key = secrets.randbits(32)
        public_key = pow(base, private_key, modulus)

        message = io.BytesIO()
        message.write(struct.pack('b', self._get_next_frame()))
        message.write(b'\xf0\x00\x08')
        message.write(struct.pack('<I', public_key))
        message.write(b'\x00\x00\x00\x00')

        await self._device.write_gatt_char(self._characteristic, message.getvalue())

        encryption_reply: EncryptionReply = await self.wait_for_message(EncryptionReply)
        if encryption_reply is None:
            raise Exception("Didn't get a public key back from the scale")

        shared_key = pow(encryption_reply.other_public_key, private_key, modulus)
        self._xxtea_key = struct.pack("@8s8x", bytes("%08x" % shared_key, "utf-8"))

    def _get_next_frame(self):
        frame = self._frame
        self._frame = (self._frame + 1) % 0x10
        return frame

    async def _send_message(self, buf):
        _LOGGER.debug("Sending message: %s" % bytes.hex(buf))
        message = io.BytesIO()
        message.write(struct.pack("4b", self._get_next_frame() + 0x10, 1, 0, len(buf)))

        padded_payload = io.BytesIO()
        padded_payload.write(buf)
        while len(padded_payload.getvalue()) % 8 > 0:
            padded_payload.write(b'\x00')

        for i in range(0, int(len(padded_payload.getvalue()) / 8)):
            message.write(xxtea.encrypt(padded_payload.getvalue()[i*8:(i+1)*8], self._xxtea_key,  padding=False))

        await self._device.write_gatt_char(self._characteristic, message.getvalue())

    async def sync_time(self, timestamp=None) -> bool:
        _LOGGER.info("Synchronizing time")
        if not timestamp:
            timestamp = int(time.time())

        message = io.BytesIO()
        message.write(struct.pack(
            "<2BH2B", 0x16, 0x00, 0x07, CMD_SYNC_TIME, 0xa8))
        message.write(struct.pack("<L", timestamp))
        message.write(b'\01')
        await self._send_message(message.getvalue())

        reply = await self.wait_for_message(SyncTimeReply)
        if reply and reply.success:
            _LOGGER.info("Successfully synchronized time")
            return True
        else:
            if not reply:
                _LOGGER.error("Didn't get response when synchronizing time")
            else:
                _LOGGER.error("Received error status after synchronizing time")
            return False

    async def user_list_new(self) -> Optional[List[UserListNewReply]]:
        _LOGGER.info("Retrieving user list")
        message = io.BytesIO()

        message.write(struct.pack(
            "<2BH2B", 0x16, 0x00, 0x02, CMD_USER_LIST_NEW, 0xa8))
        await self._send_message(message.getvalue())

        replies = []

        reply = await self.wait_for_message(UserListNewReply)
        if not reply:
            _LOGGER.error("No response after listing users")
            return None

        replies.append(reply)
        while True:
            reply = await self.wait_for_message(UserListNewReply, 2)
            if not reply:
                break
            replies.append(reply)
        return replies

    async def update_current_user_new(self, user_data: UserData):
        _LOGGER.info("Setting current user: %s" % bytes.hex(user_data.user_id))
        message = io.BytesIO()

        message.write(struct.pack(
            "<2BH2B", 0x16, 0x00, 0x1b, CMD_CURRENT_USER_NEW, 0xa8))

        payload = struct.pack('<16sHBBBBBH',
                              user_data.user_id,
                              user_data.raw_weight,
                              user_data.raw_sex,
                              user_data.age,
                              user_data.height,
                              user_data.athlete_mode,
                              user_data.only_weight,
                              user_data.last_imp)
        message.write(payload)

        await self._send_message(message.getvalue())

        reply = await self.wait_for_message(UpdateCurrentUserNewReply)
        if reply and reply.success:
            _LOGGER.info("Successfully set current user")
            return True
        else:
            if not reply:
                _LOGGER.error("Didn't get response when setting user")
            else:
                _LOGGER.error("Received error status after setting user")
            return False

    async def update_user(self, user_data: UserData):
        _LOGGER.info("Updating user: %s" % bytes.hex(user_data.user_id))
        message = io.BytesIO()

        message.write(struct.pack(
            "<2BH2B", 0x16, 0x00, 0x1b, CMD_UPDATE_USER, 0xa8))

        payload = struct.pack('<16sHBBBBBH',
                              user_data.user_id,
                              user_data.raw_weight,
                              user_data.raw_sex,
                              user_data.age,
                              user_data.height,
                              user_data.athlete_mode,
                              user_data.only_weight,
                              user_data.last_imp)
        message.write(payload)

        await self._send_message(message.getvalue())

        reply = await self.wait_for_message(UpdateUserReply)
        if reply and reply.success:
            _LOGGER.info("Successfully updated user")
            return True
        else:
            if not reply:
                _LOGGER.error("Didn't get response when updating user")
            else:
                _LOGGER.error("Received error status after updating user")
            return False

    async def update_current_user(self, user_data: UserData):
        _LOGGER.info("Setting current user: %s" % bytes.hex(user_data.user_id))
        message = io.BytesIO()

        message.write(struct.pack(
            "<2BH2B", 0x16, 0x00, 0x1b, CMD_CURRENT_USER, 0xa8))

        payload = struct.pack('<16sHBBBBB',
                              user_data.user_id,
                              user_data.raw_weight,
                              user_data.raw_sex,
                              user_data.age,
                              user_data.height,
                              user_data.athlete_mode,
                              user_data.only_weight)
        message.write(payload)

        await self._send_message(message.getvalue())

        reply = await self.wait_for_message(UpdateCurrentUserReply)
        if reply and reply.success:
            _LOGGER.info("Successfully set current user")
            return True
        else:
            if not reply:
                _LOGGER.error("Didn't get response when setting user")
            else:
                _LOGGER.error("Received error status after setting user")
            return False

    async def delete_user(self, user_id: bytes):
        _LOGGER.info("Deleting user: %s" % bytes.hex(user_id))
        message = io.BytesIO()

        message.write(struct.pack(
            "<2BH2B", 0x16, 0x00, 0x12, CMD_DEL_USER, 0xa8))

        payload = struct.pack('<16s', user_id)
        message.write(payload)

        await self._send_message(message.getvalue())

        reply = await self.wait_for_message(DeleteUserReply)
        if reply and reply.success:
            _LOGGER.info("Successfully deleted user")
            return True
        else:
            if not reply:
                _LOGGER.error("Didn't get response when deleting user")
            else:
                _LOGGER.error("Received error status after deleting user")
            return False

    async def reset_scale(self):
        _LOGGER.info("Resetting scale")
        message = io.BytesIO()

        message.write(struct.pack(
            "<2BH2B", 0x16, 0x00, 0x02, CMD_RESET, 0xa8))

        await self._send_message(message.getvalue())

        reply = await self.wait_for_message(ResetScaleReply)
        if reply and reply.success:
            _LOGGER.info("Successfully reset scale")
            return True
        else:
            if not reply:
                _LOGGER.error("Didn't get response when resetting scale")
            else:
                _LOGGER.error("Received error status after resetting scale")
            return False

    async def set_unit(self, lb):
        _LOGGER.info("Setting the units to %s" % ("lb" if lb else "kg"))
        message = io.BytesIO()

        message.write(struct.pack(
            "<2BH2B", 0x16, 0x00, 0x03, CMD_SET_UNIT, 0xa8))
        message.write(struct.pack("<B", lb))

        await self._send_message(message.getvalue())

        reply = await self.wait_for_message(SetUnitReply)
        if reply and reply.success:
            _LOGGER.info("Successfully set the units")
            return True
        else:
            if not reply:
                _LOGGER.error("Didn't get response when setting the units")
            else:
                _LOGGER.error("Received error status after setting the units")
            return False

    async def set_greeting(self, greeting):
        _LOGGER.info("Setting the greeting to %s" % greeting)
        message = io.BytesIO()

        message.write(struct.pack(
            "<2BH2B", 0x16, 0x00, 0x03, CMD_SET_HELLO, 0xa8))
        message.write(struct.pack("<B", greeting))

        await self._send_message(message.getvalue())

        reply = await self.wait_for_message(SetHelloReply)
        if reply and reply.success:
            _LOGGER.info("Successfully set the greeting")
            return True
        else:
            if not reply:
                _LOGGER.error("Didn't get response when setting the greeting")
            else:
                _LOGGER.error("Received error status after setting the greeting")
            return False

    async def send_historical_weight_data_response(self):
        _LOGGER.info("Acknowledging historical weight record")

        # Note: Responding to the historical weight message causes the scale to delete the entry from its cache
        # But if there are multiple pending historical weight entries, there's no way to get the others, except by
        # responding to them as they are sent. At least, as far as I can tell.

        message = io.BytesIO()
        message.write(struct.pack(
            "<2BH2BB", 0x16, 0x00, 0x03, CMD_HISTORY_WEIGHT_DATA, 0xa8, 0x00))

        await self._send_message(message.getvalue())


class WyzeScale(object):

    def __init__(self, mac_address):
        self._protocol = WyzeScaleProtocol(mac_address)
        self._connected = False

    async def __aenter__(self):
        await self.connect()

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        await self.disconnect()

    async def connect(self):
        if not self._connected:
            try:
                await self._protocol.connect()
                success = await self._protocol.sync_time()
                if not success:
                    raise IOError("Error sending sync time command")
                self._connected = True
            finally:
                if not self._connected:
                    await self._protocol.disconnect()

    async def disconnect(self):
        if self._connected:
            try:
                await self._protocol.disconnect()
            finally:
                self._connected = False

    async def get_users(self) -> Sequence[UserData]:
        if not self._connected:
            raise ValueError("Must call connect() before calling get_users()")

        replies = await self._protocol.user_list_new()
        users = []
        if replies:
            for reply in replies:
                users.extend(reply.users)
        return users

    async def get_weights(self, user_data: UserData):
        if not self._connected:
            raise ValueError("Must call connect() before calling get_weights()")

        result = await self._protocol.update_current_user_new(user_data)
        if not result:
            raise IOError("Error selecting user")

        message = await self._protocol.next_message()
        while message is not None:
            if isinstance(message, HistoricalWeightData):
                if user_data.user_id == message.user_id:
                    await self._protocol.send_historical_weight_data_response()
                    yield message
                else:
                    raise IOError("Unexpectedly got historical weight for a different user")
            message = await self._protocol.next_message()

    async def new_user(self, user_id, weight, sex, age, height, athlete, only_weight, last_imp):
        if not self._connected:
            raise ValueError("Must call connect() before calling new_user()")

        user_data = UserData(
            bytes.fromhex(user_id),
            int(weight * 100),
            1 if sex == "M" else 0,
            age,
            height,
            1 if athlete else 0,
            1 if only_weight else 0,
            last_imp)
        result = await self._protocol.update_current_user_new(user_data)
        if not result:
            return False

        result = await self._protocol.update_user(user_data)
        if not result:
            return False
        return True

    async def delete_user(self, user_id):
        if not self._connected:
            raise ValueError("Must call connect() before calling delete_user()")

        result = await self._protocol.delete_user(bytes.fromhex(user_id))
        if not result:
            return False
        return True

    async def reset_scale(self):
        if not self._connected:
            raise ValueError("Must call connect() before calling reset_scale()")

        result = await self._protocol.reset_scale()
        if not result:
            return False
        return True

    async def set_unit(self, lb: bool):
        if not self._connected:
            raise ValueError("Must call connect() before calling set_unit()")

        result = await self._protocol.set_unit(lb)
        if not result:
            return False
        return True

    async def set_greeting(self, greeting: bool):
        if not self._connected:
            raise ValueError("Must call connect() before calling set_greeting()")

        result = await self._protocol.set_greeting(greeting)
        if not result:
            return False
        return True

    async def live_weigh(self):
        if not self._connected:
            raise ValueError("Must call connect() before calling live_weigh")

        message = await self._protocol.next_message()
        while True:
            if isinstance(message, CurrentWeightData):
                yield message
            message = await self._protocol.next_message()
