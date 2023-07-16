import base64
import sys
import http.client
import io
import typing

"""
Данный код:
Корректно декодирует пакеты 
Корректно кодирует пакеты
Есть проверка crc8
Есть проверка на время ожидания ответа устройства
Сценарий 2 работает
Код обработки EnvSensor, но не проверен
"""


# Enums
class Dst:
    Everyone = 16383


class DevType:
    SmartHub = 1
    EnvSensor = 2
    Switch = 3
    Lamp = 4
    Socket = 5
    Clock = 6


class Cmd:
    WHOISHERE = 1
    IAMHERE = 2
    GETSTATUS = 3
    STATUS = 4
    SETSTATUS = 5
    TICK = 6


class Value:
    OFF = 0
    ON = 1


# Initial values
server_url = sys.argv[1]
server_src = int(sys.argv[2], 16)

server_serial = 1
server_dev_name = "HUB01"

server_devices = {}
server_devices_name_src = {}
server_time = 0
"""
FIXME! Почему-то, со стороны сервера на запрос get_status может прийти 2 пакета status.
Реакцией клиента будет обработка status пакета 2 раза, и он добавит в очередь packet_bytes_to_send 2 пакета get_status.
Проверка is device in server_devices_get_status_sent перед добавлением пакета get_status позволяет обойти это.
P.S. Я пробовал точно проверять что бы get_status отправлялся только при получении предыдущего status. Безрезультатно.
"""
server_devices_get_status_sent = set()
server_devices_last_packet_sent = {}

packet_bytes_to_send = b""


# Libraries
class Uleb128:
    @staticmethod
    def encode(i: int) -> bytearray:
        """Encode the int i using unsigned leb128 and return the encoded bytearray."""
        assert i >= 0
        r = []
        while True:
            byte = i & 0x7f
            i = i >> 7
            if i == 0:
                r.append(byte)
                return bytearray(r)
            r.append(0x80 | byte)

    @staticmethod
    def decode(b: bytearray) -> int:
        """Decode the unsigned leb128 encoded bytearray"""
        r = 0
        for i, e in enumerate(b):
            r = r + ((e & 0x7f) << (i * 7))
        return r

    @staticmethod
    def decode_reader(r: typing.BinaryIO) -> (int, int):
        """
        Decode the unsigned leb128 encoded from a reader, it will return two values, the actual number and the number
        of bytes read.
        """
        a = bytearray()
        while True:
            b = ord(r.read(1))
            a.append(b)
            if (b & 0x80) == 0:
                break
        return Uleb128.decode(a), len(a)


class Crc8(object):
    digest_size = 1
    block_size = 1

    _table = [0, 29, 58, 39, 116, 105, 78, 83, 232, 245, 210, 207, 156, 129, 166, 187,
              205, 208, 247, 234, 185, 164, 131, 158, 37, 56, 31, 2, 81, 76, 107, 118,
              135, 154, 189, 160, 243, 238, 201, 212, 111, 114, 85, 72, 27, 6, 33, 60,
              74, 87, 112, 109, 62, 35, 4, 25, 162, 191, 152, 133, 214, 203, 236, 241,
              19, 14, 41, 52, 103, 122, 93, 64, 251, 230, 193, 220, 143, 146, 181, 168,
              222, 195, 228, 249, 170, 183, 144, 141, 54, 43, 12, 17, 66, 95, 120, 101,
              148, 137, 174, 179, 224, 253, 218, 199, 124, 97, 70, 91, 8, 21, 50, 47,
              89, 68, 99, 126, 45, 48, 23, 10, 177, 172, 139, 150, 197, 216, 255, 226,
              38, 59, 28, 1, 82, 79, 104, 117, 206, 211, 244, 233, 186, 167, 128, 157,
              235, 246, 209, 204, 159, 130, 165, 184, 3, 30, 57, 36, 119, 106, 77, 80,
              161, 188, 155, 134, 213, 200, 239, 242, 73, 84, 115, 110, 61, 32, 7, 26,
              108, 113, 86, 75, 24, 5, 34, 63, 132, 153, 190, 163, 240, 237, 202, 215,
              53, 40, 15, 18, 65, 92, 123, 102, 221, 192, 231, 250, 169, 180, 147, 142,
              248, 229, 194, 223, 140, 145, 182, 171, 16, 13, 42, 55, 100, 121, 94, 67,
              178, 175, 136, 149, 198, 219, 252, 225, 90, 71, 96, 125, 46, 51, 20, 9,
              127, 98, 69, 88, 11, 22, 49, 44, 151, 138, 173, 176, 227, 254, 217, 196]

    def __init__(self, initial_string=b'', initial_start=0x00):
        """Create a new crc8 hash instance."""
        self._sum = initial_start
        self._initial_start = initial_start
        self._update(initial_string)

    def update(self, bytes_):
        """Update the hash object with the string arg.

        Repeated calls are equivalent to a single call with the concatenation
        of all the arguments: m.update(a); m.update(b) is equivalent
        to m.update(a+b).
        """
        self._update(bytes_)

    def digest(self):
        """Return the digest of the bytes passed to the update() method so far.

        This is a string of digest_size bytes which may contain non-ASCII
        characters, including null bytes.
        """
        return self._digest()

    def hexdigest(self):
        """Return digest() as hexadecimal string.

        Like digest() except the digest is returned as a string of double
        length, containing only hexadecimal digits. This may be used to
        exchange the value safely in email or other non-binary environments.
        """
        return hex(self._sum)[2:].zfill(2)

    def _update(self, bytes_):
        if isinstance(bytes_, str):
            raise TypeError("Unicode-objects must be encoded before hashing")
        elif not isinstance(bytes_, (bytes, bytearray)):
            raise TypeError("object supporting the buffer API required")
        table = self._table
        _sum = self._sum
        for byte in bytes_:
            _sum = table[_sum ^ byte]
        self._sum = _sum

    def _digest(self):
        return bytes([self._sum])

    def copy(self):
        """Return a copy ("clone") of the hash object.

        This can be used to efficiently compute the digests of strings that
        share a common initial substring.
        """
        crc = Crc8()
        crc._sum = self._sum
        return crc

    def reset(self):
        """Resets the hash object to its initial state."""
        self._sum = self._initial_start


# Utilities
def decode_base64_unpaded(input_string):
    input_bytes = input_string.encode("ascii")
    input_len = len(input_bytes)
    padding = b"=" * (3 - ((input_len + 3) % 4))

    return base64.b64decode(input_bytes + padding, altchars=b"-_")


def encode_base64_unpaded(bytes_to_encode):
    return base64.b64encode(bytes_to_encode, altchars=b"-_").replace(b"=", b"")


def decode_packet(packet_bytes):
    packet = {"length": packet_bytes[0], "payload": {"cmd_body": {}}, "crc8": packet_bytes[packet_bytes[0] + 1]}

    crc8 = Crc8()
    crc8.update(packet_bytes[1:packet_bytes[0] + 2])
    if crc8.digest() != b'\x00':
        return None

    main_offset = 0
    payload = packet_bytes[1:-1]

    packet["payload"]["src"], offset = Uleb128.decode_reader(io.BytesIO(payload[main_offset:]))
    main_offset += offset
    packet["payload"]["dst"], offset = Uleb128.decode_reader(io.BytesIO(payload[main_offset:]))
    main_offset += offset
    packet["payload"]["serial"], offset = Uleb128.decode_reader(io.BytesIO(payload[main_offset:]))
    main_offset += offset

    packet["payload"]["dev_type"] = payload[main_offset]
    main_offset += 1
    packet["payload"]["cmd"] = payload[main_offset]
    main_offset += 1

    if packet["payload"]["dev_type"] == DevType.SmartHub:
        if packet["payload"]["cmd"] == Cmd.WHOISHERE or packet["payload"]["cmd"] == Cmd.IAMHERE:
            dev_name_length = payload[main_offset]
            main_offset += 1

            packet["payload"]["cmd_body"]["dev_name"] = payload[main_offset:main_offset + dev_name_length].decode()

    if packet["payload"]["dev_type"] == DevType.EnvSensor:
        if packet["payload"]["cmd"] == Cmd.WHOISHERE or packet["payload"]["cmd"] == Cmd.IAMHERE:
            dev_name_length = payload[main_offset]
            main_offset += 1

            packet["payload"]["cmd_body"]["dev_name"] = payload[main_offset:main_offset + dev_name_length].decode()
            main_offset += dev_name_length

            packet["payload"]["cmd_body"]["dev_props"] = {}

            packet["payload"]["cmd_body"]["dev_props"]["sensors"] = payload[main_offset]
            main_offset += 1

            packet["payload"]["cmd_body"]["dev_props"]["triggers"] = []
            triggers_length = payload[main_offset]
            main_offset += 1

            for i in range(triggers_length):
                trigger = {"op": payload[main_offset]}
                main_offset += 1

                trigger["value"], offset = Uleb128.decode_reader(io.BytesIO(payload[main_offset:]))
                main_offset += offset

                name_length = payload[main_offset]
                main_offset += 1

                trigger["name"] = payload[main_offset:main_offset + name_length].decode()
                main_offset += name_length

                packet["payload"]["cmd_body"]["dev_props"]["triggers"].append(trigger)

        if packet["payload"]["cmd"] == Cmd.STATUS:
            packet["payload"]["cmd_body"]["values"] = []

            values_length = payload[main_offset]
            main_offset += 1

            for i in range(values_length):
                value, offset = Uleb128.decode_reader(io.BytesIO(payload[main_offset:]))
                main_offset += offset

                packet["payload"]["cmd_body"]["values"].append(value)

    if packet["payload"]["dev_type"] == DevType.Switch:
        if packet["payload"]["cmd"] == Cmd.WHOISHERE or packet["payload"]["cmd"] == Cmd.IAMHERE:
            dev_name_length = payload[main_offset]
            main_offset += 1

            packet["payload"]["cmd_body"]["dev_name"] = payload[main_offset:main_offset + dev_name_length].decode()
            main_offset += dev_name_length

            packet["payload"]["cmd_body"]["dev_props"] = {}

            packet["payload"]["cmd_body"]["dev_props"]["dev_names"] = []
            dev_names_length = payload[main_offset]
            main_offset += 1

            for i in range(dev_names_length):
                dev_name_arr_length = payload[main_offset]
                main_offset += 1

                packet["payload"]["cmd_body"]["dev_props"]["dev_names"].append(
                    payload[main_offset:main_offset + dev_name_arr_length].decode())
                main_offset += dev_name_arr_length

        if packet["payload"]["cmd"] == Cmd.STATUS:
            packet["payload"]["cmd_body"]["value"] = payload[main_offset]

    if packet["payload"]["dev_type"] == DevType.Lamp or packet["payload"]["dev_type"] == DevType.Socket:
        if packet["payload"]["cmd"] == Cmd.WHOISHERE or packet["payload"]["cmd"] == Cmd.IAMHERE:
            dev_name_length = payload[main_offset]
            main_offset += 1

            packet["payload"]["cmd_body"]["dev_name"] = payload[main_offset:main_offset + dev_name_length].decode()

        if packet["payload"]["cmd"] == Cmd.STATUS or packet["payload"]["cmd"] == Cmd.SETSTATUS:
            packet["payload"]["cmd_body"]["value"] = payload[main_offset]

    if packet["payload"]["dev_type"] == DevType.Clock:
        if packet["payload"]["cmd"] == Cmd.IAMHERE:
            dev_name_length = payload[main_offset]
            main_offset += 1

            packet["payload"]["cmd_body"]["dev_name"] = payload[main_offset:main_offset + dev_name_length].decode()

        if packet["payload"]["cmd"] == Cmd.TICK:
            packet["payload"]["cmd_body"]["timestamp"], offset = Uleb128.decode_reader(
                io.BytesIO(payload[main_offset:]))

            processing_clock(packet)

    if packet["payload"]["cmd_body"] == {}:
        del packet["payload"]["cmd_body"]

    return packet


def decode_packets(packets_b64):
    packets_arr = []

    try:
        packets_bytes = decode_base64_unpaded(packets_b64)
    except:
        return None

    while True:
        packet = decode_packet(packets_bytes)
        if packet is None:
            continue

        packets_arr.append(packet)

        packets_bytes = packets_bytes[packet["length"] + 2:]

        if packets_bytes == b'':
            break

    return packets_arr


def decode_packets_test():
    print("SmartHub, WHOISHERE (1, 1): ", decode_packets('DAH_fwEBAQVIVUIwMeE')[0] == {
        "length": 12,
        "payload": {
            "src": 1,
            "dst": 16383,
            "serial": 1,
            "dev_type": 1,
            "cmd": 1,
            "cmd_body": {
                "dev_name": "HUB01"
            }
        },
        "crc8": 225
    })
    print("SmartHub, IAMHERE (1, 2): ", decode_packets('DAH_fwIBAgVIVUIwMak')[0] == {
        "length": 12,
        "payload": {
            "src": 1,
            "dst": 16383,
            "serial": 2,
            "dev_type": 1,
            "cmd": 2,
            "cmd_body": {
                "dev_name": "HUB01"
            }
        },
        "crc8": 169
    })
    print("EnvSensor, WHOISHERE (2, 1): ",
          decode_packets('OAL_fwMCAQhTRU5TT1IwMQ8EDGQGT1RIRVIxD7AJBk9USEVSMgCsjQYGT1RIRVIzCAAGT1RIRVI03Q')[0] == {
              "length": 56,
              "payload": {
                  "src": 2,
                  "dst": 16383,
                  "serial": 3,
                  "dev_type": 2,
                  "cmd": 1,
                  "cmd_body": {
                      "dev_name": "SENSOR01",
                      "dev_props": {
                          "sensors": 15,
                          "triggers": [
                              {
                                  "op": 12,
                                  "value": 100,
                                  "name": "OTHER1"
                              },
                              {
                                  "op": 15,
                                  "value": 1200,
                                  "name": "OTHER2"
                              },
                              {
                                  "op": 0,
                                  "value": 100012,
                                  "name": "OTHER3"
                              },
                              {
                                  "op": 8,
                                  "value": 0,
                                  "name": "OTHER4"
                              }
                          ]
                      }
                  }
              },
              "crc8": 221
          })
    print("EnvSensor, IAMHERE (2, 2): ",
          decode_packets('OAL_fwQCAghTRU5TT1IwMQ8EDGQGT1RIRVIxD7AJBk9USEVSMgCsjQYGT1RIRVIzCAAGT1RIRVI09w')[0] == {
              "length": 56,
              "payload": {
                  "src": 2,
                  "dst": 16383,
                  "serial": 4,
                  "dev_type": 2,
                  "cmd": 2,
                  "cmd_body": {
                      "dev_name": "SENSOR01",
                      "dev_props": {
                          "sensors": 15,
                          "triggers": [
                              {
                                  "op": 12,
                                  "value": 100,
                                  "name": "OTHER1"
                              },
                              {
                                  "op": 15,
                                  "value": 1200,
                                  "name": "OTHER2"
                              },
                              {
                                  "op": 0,
                                  "value": 100012,
                                  "name": "OTHER3"
                              },
                              {
                                  "op": 8,
                                  "value": 0,
                                  "name": "OTHER4"
                              }
                          ]
                      }
                  }
              },
              "crc8": 247
          })
    print("EnvSensor, GETSTATUS (2, 3): ", decode_packets('BQECBQIDew')[0] == {
        "length": 5,
        "payload": {
            "src": 1,
            "dst": 2,
            "serial": 5,
            "dev_type": 2,
            "cmd": 3
        },
        "crc8": 123
    })
    print("EnvSensor, STATUS (2, 4): ", decode_packets('EQIBBgIEBKUB4AfUjgaMjfILrw')[0] == {
        "length": 17,
        "payload": {
            "src": 2,
            "dst": 1,
            "serial": 6,
            "dev_type": 2,
            "cmd": 4,
            "cmd_body": {
                "values": [
                    165,
                    992,
                    100180,
                    24938124
                ]
            }
        },
        "crc8": 175
    })
    print("Switch, WHOISHERE (3, 1): ", decode_packets('IgP_fwcDAQhTV0lUQ0gwMQMFREVWMDEFREVWMDIFREVWMDO1')[0] == {
        "length": 34,
        "payload": {
            "src": 3,
            "dst": 16383,
            "serial": 7,
            "dev_type": 3,
            "cmd": 1,
            "cmd_body": {
                "dev_name": "SWITCH01",
                "dev_props": {
                    "dev_names": [
                        "DEV01",
                        "DEV02",
                        "DEV03"
                    ]
                }
            }
        },
        "crc8": 181
    })
    print("Switch, IAMHERE (3, 2): ", decode_packets('IgP_fwgDAghTV0lUQ0gwMQMFREVWMDEFREVWMDIFREVWMDMo')[0] == {
        "length": 34,
        "payload": {
            "src": 3,
            "dst": 16383,
            "serial": 8,
            "dev_type": 3,
            "cmd": 2,
            "cmd_body": {
                "dev_name": "SWITCH01",
                "dev_props": {
                    "dev_names": [
                        "DEV01",
                        "DEV02",
                        "DEV03"
                    ]
                }
            }
        },
        "crc8": 40
    })
    print("Switch, GETSTATUS (3, 3): ", decode_packets('BQEDCQMDoA')[0] == {
        "length": 5,
        "payload": {
            "src": 1,
            "dst": 3,
            "serial": 9,
            "dev_type": 3,
            "cmd": 3
        },
        "crc8": 160
    })
    print("Switch, STATUS (3, 4): ", decode_packets('BgMBCgMEAac')[0] == {
        "length": 6,
        "payload": {
            "src": 3,
            "dst": 1,
            "serial": 10,
            "dev_type": 3,
            "cmd": 4,
            "cmd_body": {
                "value": 1
            }
        },
        "crc8": 167
    })
    print("Lamp, WHOISHERE (4, 1): ", decode_packets('DQT_fwsEAQZMQU1QMDG8')[0] == {
        "length": 13,
        "payload": {
            "src": 4,
            "dst": 16383,
            "serial": 11,
            "dev_type": 4,
            "cmd": 1,
            "cmd_body": {
                "dev_name": "LAMP01"
            }
        },
        "crc8": 188
    })
    print("Lamp, IAMHERE (4, 2): ", decode_packets('DQT_fwwEAgZMQU1QMDGU')[0] == {
        "length": 13,
        "payload": {
            "src": 4,
            "dst": 16383,
            "serial": 12,
            "dev_type": 4,
            "cmd": 2,
            "cmd_body": {
                "dev_name": "LAMP01"
            }
        },
        "crc8": 148
    })
    print("Lamp, GETSTATUS (4, 3): ", decode_packets('BQEEDQQDqw')[0] == {
        "length": 5,
        "payload": {
            "src": 1,
            "dst": 4,
            "serial": 13,
            "dev_type": 4,
            "cmd": 3
        },
        "crc8": 171
    })
    print("Lamp, STATUS (4, 4): ", decode_packets('BgQBDgQEAaw')[0] == {
        "length": 6,
        "payload": {
            "src": 4,
            "dst": 1,
            "serial": 14,
            "dev_type": 4,
            "cmd": 4,
            "cmd_body": {
                "value": 1
            }
        },
        "crc8": 172
    })
    print("Lamp, SETSTATUS (4, 5): ", decode_packets('BgEEDwQFAeE')[0] == {
        "length": 6,
        "payload": {
            "src": 1,
            "dst": 4,
            "serial": 15,
            "dev_type": 4,
            "cmd": 5,
            "cmd_body": {
                "value": 1
            }
        },
        "crc8": 225
    })
    print("Socket, WHOISHERE (5, 1): ", decode_packets('DwX_fxAFAQhTT0NLRVQwMQ4')[0] == {
        "length": 15,
        "payload": {
            "src": 5,
            "dst": 16383,
            "serial": 16,
            "dev_type": 5,
            "cmd": 1,
            "cmd_body": {
                "dev_name": "SOCKET01"
            }
        },
        "crc8": 14
    })
    print("Socket, IAMHERE (5, 2): ", decode_packets('DwX_fxEFAghTT0NLRVQwMc0')[0] == {
        "length": 15,
        "payload": {
            "src": 5,
            "dst": 16383,
            "serial": 17,
            "dev_type": 5,
            "cmd": 2,
            "cmd_body": {
                "dev_name": "SOCKET01"
            }
        },
        "crc8": 205
    })
    print("Socket, GETSTATUS (5, 3): ", decode_packets('BQEFEgUD5A')[0] == {
        "length": 5,
        "payload": {
            "src": 1,
            "dst": 5,
            "serial": 18,
            "dev_type": 5,
            "cmd": 3
        },
        "crc8": 228
    })
    print("Socket, STATUS (5, 4): ", decode_packets('BgUBEwUEAQ8')[0] == {
        "length": 6,
        "payload": {
            "src": 5,
            "dst": 1,
            "serial": 19,
            "dev_type": 5,
            "cmd": 4,
            "cmd_body": {
                "value": 1
            }
        },
        "crc8": 15
    })
    print("Socket, SETSTATUS (5, 5): ", decode_packets('BgEFFAUFAQc')[0] == {
        "length": 6,
        "payload": {
            "src": 1,
            "dst": 5,
            "serial": 20,
            "dev_type": 5,
            "cmd": 5,
            "cmd_body": {
                "value": 1
            }
        },
        "crc8": 7
    })
    print("Clock, IAMHERE (6, 2): ", decode_packets('Dgb_fxUGAgdDTE9DSzAxsw')[0] == {
        "length": 14,
        "payload": {
            "src": 6,
            "dst": 16383,
            "serial": 21,
            "dev_type": 6,
            "cmd": 2,
            "cmd_body": {
                "dev_name": "CLOCK01"
            }
        },
        "crc8": 179
    })
    print("Clock, TICK (6, 6): ", decode_packets('DAb_fxgGBpabldu2NNM')[0] == {
        "length": 12,
        "payload": {
            "src": 6,
            "dst": 16383,
            "serial": 24,
            "dev_type": 6,
            "cmd": 6,
            "cmd_body": {
                "timestamp": 1801393098134
            }
        },
        "crc8": 211
    })


def encode_packet_and_add_bytes_to_send(payload):
    global packet_bytes_to_send

    packet_bytes = b''

    payload_bytes = b''
    payload_bytes += Uleb128.encode(payload["src"])
    payload_bytes += Uleb128.encode(payload["dst"])
    payload_bytes += Uleb128.encode(payload["serial"])
    payload_bytes += payload["dev_type"].to_bytes(1, 'little')
    payload_bytes += payload["cmd"].to_bytes(1, 'little')

    if payload["cmd"] == Cmd.SETSTATUS:
        if payload["dev_type"] == DevType.Lamp or payload["dev_type"] == DevType.Socket:
            payload_bytes += payload["cmd_body"]["value"].to_bytes(1, 'little')

    elif payload["cmd"] == Cmd.WHOISHERE:
        payload_bytes += len(payload["cmd_body"]["dev_name"]).to_bytes(1, 'little')
        payload_bytes += payload["cmd_body"]["dev_name"].encode('ascii')

    crc8 = Crc8()
    crc8.update(payload_bytes)

    packet_bytes += len(payload_bytes).to_bytes(1, 'little')
    packet_bytes += payload_bytes
    packet_bytes += crc8.digest()

    packet_bytes_to_send += packet_bytes


def sensors_byte_mask(byte):
    return [
        bool(byte & 0x1),
        bool(byte & 0x2),
        bool(byte & 0x4),
        bool(byte & 0x8)
    ]


def make_request(data):
    global server_serial

    connection = http.client.HTTPConnection(server_url.split("//")[1])
    connection.request("POST", "/", data)
    response = connection.getresponse()

    server_serial += 1

    if response.status == 204:
        sys.exit(0)

    if response.status != 200 and response.status != 204:
        sys.exit(99)

    return response


# Processing Packets
def processing_who_is_here(packet):
    encode_packet_and_add_bytes_to_send({
        "src": server_src,
        "dst": Dst.Everyone,
        "serial": server_serial,
        "dev_type": packet["payload"]["dev_type"],
        "cmd": Cmd.IAMHERE,
        "cmd_body": {
            "dev_name": "HUB01"
        }
    })


def processing_env_sensor(packet):
    if packet["payload"]["src"] not in server_devices_last_packet_sent or server_time > server_devices_last_packet_sent[
        packet["payload"]["src"]]:
        encode_packet_and_add_bytes_to_send({
            "src": server_src,
            "dst": packet["payload"]["src"],
            "serial": server_serial,
            "dev_type": packet["payload"]["dev_type"],
            "cmd": Cmd.GETSTATUS,
        })
    server_devices_last_packet_sent[packet["payload"]["src"]] = server_time

    if packet["payload"]["cmd"] == Cmd.STATUS:
        server_devices[packet["payload"]["src"]]["values"] = packet["payload"]["cmd_body"]["values"]

        sensors = sensors_byte_mask(server_devices[packet["payload"]["src"]]["sensors"])

        values = {}
        i = 0
        if sensors[0]:
            values[0] = packet["payload"]["cmd_body"]["values"][i]
            i += 1
        if sensors[1]:
            values[1] = packet["payload"]["cmd_body"]["values"][i]
            i += 1
        if sensors[2]:
            values[2] = packet["payload"]["cmd_body"]["values"][i]
            i += 1
        if sensors[3]:
            values[3] = packet["payload"]["cmd_body"]["values"][i]

        for trigger in server_devices[packet["payload"]["src"]]["triggers"]:
            op_bits = bin(trigger["op"])[2:]
            for i in range(4 - len(op_bits)):
                op_bits = "0" + op_bits

            value = op_bits[3]
            comparison = op_bits[2]
            sensor_type = int(op_bits[:2], 2)

            enable = False
            if comparison == 0:
                if values[sensor_type] < trigger["value"]:
                    enable = True
            elif comparison == 1:
                if values[sensor_type] > trigger["value"]:
                    enable = True

            if enable:
                server_devices_last_packet_sent[server_devices_name_src[trigger["name"]]] = server_time

                encode_packet_and_add_bytes_to_send({
                    "src": server_src,
                    "dst": server_devices_name_src[trigger["name"]],
                    "serial": server_serial,
                    "dev_type": trigger["name"],
                    "cmd": Cmd.SETSTATUS,
                    "cmd_body": {
                        "value": value
                    }
                })


def processing_switch(packet):
    if packet["payload"]["src"] not in server_devices_get_status_sent:
        encode_packet_and_add_bytes_to_send({
            "src": server_src,
            "dst": packet["payload"]["src"],
            "serial": server_serial,
            "dev_type": packet["payload"]["dev_type"],
            "cmd": Cmd.GETSTATUS,
        })

        server_devices_last_packet_sent[packet["payload"]["src"]] = server_time
        server_devices_get_status_sent.add(packet["payload"]["src"])

    if packet["payload"]["cmd"] == Cmd.STATUS:
        server_devices[packet["payload"]["src"]]["value"] = packet["payload"]["cmd_body"]["value"]

        for dev_name in server_devices[packet["payload"]["src"]]["dev_names"]:
            server_devices_last_packet_sent[server_devices_name_src[dev_name]] = server_time

            encode_packet_and_add_bytes_to_send({
                "src": server_src,
                "dst": server_devices_name_src[dev_name],
                "serial": server_serial,
                "dev_type": server_devices[server_devices_name_src[dev_name]]["dev_type"],
                "cmd": Cmd.SETSTATUS,
                "cmd_body": {
                    "value": packet["payload"]["cmd_body"]["value"]
                }
            })


def processing_lamp_or_socket(packet):
    if packet["payload"]["cmd"] == Cmd.STATUS:
        server_devices[packet["payload"]["src"]]["value"] = packet["payload"]["cmd_body"]["value"]


def processing_clock(packet):
    global server_time

    if packet["payload"]["cmd"] == Cmd.TICK:
        server_time = packet["payload"]["cmd_body"]["timestamp"]


def processing_commands(packet):
    if packet["payload"]["cmd"] == Cmd.WHOISHERE:
        processing_who_is_here(packet)
        server_devices_last_packet_sent.pop(packet["payload"]["src"])
    elif packet["payload"]["src"] in server_devices_last_packet_sent and (
            server_time - server_devices_last_packet_sent[packet["payload"]["src"]]) >= 300:
        return None

    if packet["payload"]["cmd"] == Cmd.WHOISHERE or packet["payload"]["cmd"] == Cmd.IAMHERE:
        server_devices[packet["payload"]["src"]] = {
            "dev_name": packet["payload"]["cmd_body"]["dev_name"],
            "dev_type": packet["payload"]["dev_type"]
        }
        server_devices_name_src[packet["payload"]["cmd_body"]["dev_name"]] = packet["payload"]["src"]

        if packet["payload"]["dev_type"] == DevType.EnvSensor:
            server_devices[packet["payload"]["src"]]["sensors"] = packet["payload"]["cmd_body"]["dev_props"]["sensors"]
            server_devices[packet["payload"]["src"]]["triggers"] = packet["payload"]["cmd_body"]["dev_props"][
                "triggers"]

        elif packet["payload"]["dev_type"] == DevType.Switch:
            server_devices[packet["payload"]["src"]]["dev_names"] = packet["payload"]["cmd_body"]["dev_props"][
                "dev_names"]

    if packet["payload"]["dev_type"] == DevType.EnvSensor:
        processing_env_sensor(packet)

    elif packet["payload"]["dev_type"] == DevType.Switch:
        processing_switch(packet)

    elif packet["payload"]["dev_type"] == DevType.Lamp or packet["payload"]["dev_type"] == DevType.Socket:
        processing_lamp_or_socket(packet)


def main():
    global packet_bytes_to_send

    encode_packet_and_add_bytes_to_send({
        "src": server_src,
        "dst": Dst.Everyone,
        "serial": server_serial,
        "dev_type": DevType.SmartHub,
        "cmd": Cmd.WHOISHERE,
        "cmd_body": {
            "dev_name": server_dev_name
        }
    })

    while True:
        packets_arr = decode_packets(make_request(encode_base64_unpaded(packet_bytes_to_send)).read().decode())
        packet_bytes_to_send = b""
        server_devices_get_status_sent.clear()

        if packets_arr is None:
            continue

        for packet in packets_arr:
            processing_commands(packet)


if __name__ == "__main__":
    # if len(sys.argv) == 3 and sys.argv[2] == "--test":
    #     decode_packets_test()
    # else:
    main()
