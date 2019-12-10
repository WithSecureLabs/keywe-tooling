import binascii

def make_common_key(bdaddr):
    k = binascii.unhexlify(bdaddr.replace(b':',b''))
    key = list(bytes(b'[REDACTED]'))
    offset = k[1] % 5
    key[offset+0] = k[1]
    key[offset+2] = k[2]
    key[offset+4] = k[3]
    key[offset+6] = k[4]
    key[offset+8] = k[5]
    return bytes(key)

def make_door_key(app, door):
    magic = list(b'[REDACTED]')
    app_first_sum = (app[0] + app[1] + app[2]) & 0xff
    door_first_sum = (door[0] + door[1] + door[2]) & 0xff
    app_second_sum = (app[3] + app[4] + app[5]) & 0xff
    door_second_sum = (door[3] + door[4] + door[5]) & 0xff
    app_third_sum = (app[6] + app[7] + app[8]) & 0xff
    door_third_sum = (door[6] + door[7] + door[8]) & 0xff
    app_fourth_sum = (app[9] + app[10] + app[11]) & 0xff
    door_fourth_sum = (door[9] + door[10] + door[11]) & 0xff
    helper = (app_second_sum + 0x50) & 0xff

    magic[0] = (door_first_sum + 0x6f) & 0xff
    magic[1] = helper
    magic[2] += door_third_sum
    magic[3] += app_first_sum
    magic[4] += door_second_sum
    magic[5] += app_third_sum
    magic[6] += door_first_sum
    magic[7] += app_second_sum
    magic[8] += door_third_sum
    magic[9] += app_first_sum   # app_first_sum -> w12
    magic[10] += door_second_sum
    magic[11] += app_third_sum
    magic[12] += door_first_sum # door_third_sum -> sp[8]
    magic[13] += app_second_sum
    magic[14] += door_third_sum
    magic[15] += app_first_sum

    offset = app_first_sum & 0x1

    magic[offset] = door_first_sum ^ 0x2
    magic[offset+2] = door_second_sum ^ 0x2
    magic[offset+4] = door_third_sum ^ 0x02
    magic[offset+6] = door_fourth_sum ^ 0x2    # ???

    for i in range(2,16):
        magic[i] &= 0xff

    return bytes(magic)

def make_app_key(app, door):
    magic = list(b'[REDACTED]')
    app_first_sum = (app[0] + app[1] + app[2]) & 0xff
    door_first_sum = (door[0] + door[1] + door[2]) & 0xff
    app_second_sum = (app[3] + app[4] + app[5]) & 0xff
    door_second_sum = (door[3] + door[4] + door[5]) & 0xff        
    app_third_sum = (app[6] + app[7] + app[8]) & 0xff
    door_third_sum = (door[6] + door[7] + door[8]) & 0xff
    app_fourth_sum = (app[9] + app[10] + app[11]) & 0xff
    door_fourth_sum = (door[9] + door[10] + door[11]) & 0xff

    magic[0] = (app_first_sum + 0x50) & 0xff
    magic[1] = (door_second_sum - 0x57) & 0xff
    magic[2] += app_third_sum
    magic[3] += door_first_sum
    magic[4] += app_second_sum
    magic[5] += door_third_sum
    magic[6] += app_first_sum
    magic[7] += door_second_sum
    magic[8] += app_third_sum
    magic[9] += door_first_sum
    magic[10] += app_second_sum
    magic[11] += door_third_sum
    magic[12] += app_first_sum
    magic[13] += door_second_sum
    magic[14] += app_third_sum
    magic[15] += door_first_sum

    offset = 8 | (door_first_sum & 1)

    magic[offset] = door_first_sum
    magic[offset+2] = door_second_sum
    magic[offset+4] = door_third_sum
    magic[offset+6] = door_fourth_sum

    for i in range(2,16):
        magic[i] &= 0xff

    return bytes(magic)

