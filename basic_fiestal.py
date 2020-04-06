# BASIC FIESTAL CIPHER

import hashlib
import base64
import binascii

salt = "this is pretty amazing salt"
rounds = 8
blocksize = 8


def xor(s1, s2):
    # s1, s2 are str
    return ''.join(chr(ord(a) ^ ord(b)) for a, b in zip(s1, s2))


def key_256(key):
    return hashlib.sha256((key + salt).encode()).hexdigest()


def scramble(data, key, i):
    # data, key in str
    # str -> bin -> int

    data = ''.join(['{:08b}'.format(ord(i)) for i in str(data)])
    key = ''.join(['{:08b}'.format(ord(i)) for i in str(key)])

    data = int(data, 2)
    key = int(key, 2)

    # print(data, key, i)
    result = pow((data * key), i)
    res = bin(result)

    # return ''.join(chr(int(res[i: i+8], 2)) for i in )

    return ''.join([chr(int(res[i:i + 8], 2)) for i in range(0, len(res), 8)])


def encrypt(key, message, mode):
    cipher = ''

    message = [message[i:i + blocksize] for i in range(0, len(message), blocksize)]
    if len(message[-1]) < blocksize:
        message[-1] += ' ' * (blocksize - len(message[-1]))
    # print(message)

    key = key_256(key)
    initial_key = key

    for block in message:
        L = [""] * (rounds + 1)
        R = [""] * (rounds + 1)

        L[0] = block[:blocksize // 2]
        R[0] = block[blocksize // 2:]

        # print('L', L)
        # print('R', R)
        # print()

        for i in range(1, rounds + 1):
            L[i] = R[i - 1]

            if mode == 'cbc':
                if i == 1:
                    key = initial_key
                else:
                    key = hashlib.sha256((L[i] + initial_key).encode()).hexdigest()

            R[i] = xor(L[i - 1], scramble(R[i - 1], key, i))

        cipher += L[rounds] + R[rounds]
    # print('L', L)
    # print('R', R)
    # print()
    # print(cipher)
    return cipher


def decrypt(key, ciphertext, mode):
    print('This is decrypt')
    message = ""
    blocksize = 8
    rounds = 8

    ciphertext = [ciphertext[i:i + blocksize] for i in range(0, len(ciphertext), blocksize)]
    if len(ciphertext[-1]) < blocksize:
        ciphertext[-1] += ' ' * (blocksize - len(ciphertext[-1]))

    # generate a 256 bit key based off the user inputted key
    key = key_256(key)
    key_initial = key

    for block in ciphertext:

        L = [""] * (rounds + 1)
        R = [""] * (rounds + 1)
        L[rounds] = block[:blocksize // 2]
        R[rounds] = block[blocksize // 2:]

        for i in range(rounds, 0, -1):

            if (mode == "cbc"):
                key = hashlib.sha256((L[i] + key_initial).encode()).hexdigest()

                if (i == 1):
                    key = key_initial

            R[i - 1] = L[i]
            L[i - 1] = xor(R[i], scramble(L[i], key, i))

        message += (L[0] + R[0])

    return message


oper = input('1. Encryption, 2. Decryption ?: ')
mode = input('Mode: 1. ECB, 2. CBC: ')

if oper == '1':
    msg = input('Enter message: ')
    key = input('Enter key: ')
    if mode == '1':
        enc = encrypt(key, msg, 'ecb')
    elif mode == '2':
        enc = encrypt(key, msg, 'cbc')
    else:
        print('Invalid Mode')

    print('Cipher:', enc)
    enc = bytearray(enc.encode())

    print('Hex cipher:', binascii.hexlify(enc))
    print('Base64 version:', base64.b64encode(enc))

elif oper == '2':
    msg = input('Enter cipher: ')
    key = input('Enter key: ')
    if mode == '1':
        dec = decrypt(key, msg, 'ecb')
    elif mode == '2':
        dec = decrypt(key, msg, 'cbc')
    else:
        print('Invalid Mode')

    print('Message:', dec)

else:
    print('INVALID INPUT')
