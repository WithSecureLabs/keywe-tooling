"""
Script to run KeyWe on a rooted device
As root checks are performed throughout the app execution,
this replaces the isRooted() function return value :P
"""
from frida import get_device_manager
from sys import exit, argv
from traceback import print_stack as print_exception

# load the script that'll get injected
script_content = ' '
print('[ ] Trying to load the script...')
try:
    with open('disable_root_detection.js') as script_file:
        script_content = script_file.read()
except Exception as e:
    print_exception(e)

if not script_content:
    print('[-] Could not load the script!')
    exit(1)

def on_message(message, data):
    print("[{}] -> {}".format(message, data))

print('[ ] Finding the device to use...')
device_list = get_device_manager().enumerate_devices()
if len(device_list) == 0:
    print('[-] No devices found')
    exit(2)

# get the last device on the list (let's assume there's just one)
device = device_list[-1]
print(
    '[+] All good, using {} ({}, type: {})'.format(
        device.name,
        device.id,
        device.type
    )
)

# attach to the KeyWe app
print('[ ] Spawning the app...')
pid = device.spawn(["com.guardtec.keywe"])
print('[+] App spawned with PID={}'.format(pid))

print('[ ] Attaching to the process...')
session = device.attach(pid)
print('[+] Attached!')

# create the script object from loaded content
script = session.create_script(script_content)
script.on('message', on_message)
print('[ ] Attempting to inject the script...')
script.load()
print('[+] Script injected, all good!')

print('[+] Resuming process...')
device.resume(pid)

input()

session.detach()
