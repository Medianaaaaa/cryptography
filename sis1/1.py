import os

# AES S-box
s_box = [
    # 0    1    2    3    4    5    6    7    8    9    a    b    c    d    e    f
    0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76, # 0
    0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0, # 1
    0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15, # 2
    0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75, # 3
    0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84, # 4
    0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf, # 5
    0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8, # 6
    0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2, # 7
    0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73, # 8
    0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb, # 9
    0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79, # a
    0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08, # b
    0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a, # c
    0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e, # d
    0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf, # e
    0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16  # f
]

# AES round constant
Rcon = [
    0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36
]

# AES S-box inverse
inv_s_box = [0] * 256
for i in range(256):
    inv_s_box[s_box[i]] = i

# AES round constant lookup function
def aes_rcon(i):
    c = 1
    if i == 0:
        return 0
    while i != 1:
        b = c & 0x80
        c <<= 1
        if b:
            c ^= 0x1b
        i -= 1
    return c

# AES substitution layer (S-box)
def sub_bytes(state):
    for i in range(len(state)):
        state[i] = s_box[state[i]]

# AES inverse substitution layer (inverse S-box)
def inv_sub_bytes(state):
    for i in range(len(state)):
        state[i] = inv_s_box[state[i]]

# AES shift rows operation
def shift_rows(state):
    temp = state[1]
    state[1] = state[5]
    state[5] = state[9]
    state[9] = state[13]
    state[13] = temp

    temp = state[2]
    state[2] = state[10]
    state[10] = temp
    temp = state[6]
    state[6] = state[14]
    state[14] = temp

    temp = state[3]
    state[3] = state[15]
    state[15] = state[11]
    state[11] = state[7]
    state[7] = temp

# AES inverse shift rows operation
def inv_shift_rows(state):
    temp = state[1]
    state[1] = state[13]
    state[13] = state[9]
    state[9] = state[5]
    state[5] = temp

    temp = state[2]
    state[2] = state[10]
    state[10] = temp
    temp = state[6]
    state[6] = state[14]
    state[14] = temp

    temp = state[15]
    state[15] = state[11]
    state[11] = state[7]
    state[7] = state[3]
    state[3] = temp

# AES mix columns operation
def mix_columns(state):
    temp = bytearray(16)
    for i in range(0, 16, 4):
        temp[i]   = (state[i] << 1 ^ (state[i + 1] << 1) ^ state[i + 1] ^ state[i + 2] ^ state[i + 3]) % 256
        temp[i+1] = (state[i] ^ (state[i + 1] << 1) ^ (state[i + 2] << 1) ^ state[i + 2] ^ state[i + 3]) % 256
        temp[i+2] = (state[i] ^ state[i + 1] ^ (state[i + 2] << 1) ^ (state[i + 3] << 1) ^ state[i + 3]) % 256
        temp[i+3] = ((state[i] << 1) ^ state[i] ^ state[i + 1] ^ state[i + 2] ^ (state[i + 3] << 1)) % 256
    for i in range(16):
        state[i] = temp[i]

# AES inverse mix columns operation
def inv_mix_columns(state):
    temp = bytearray(16)
    for i in range(0, 16, 4):
        temp[i]   = (state[i] * 0x0E ^ state[i + 1] * 0x0B ^ state[i + 2] * 0x0D ^ state[i + 3] * 0x09) % 256
        temp[i+1] = (state[i] * 0x09 ^ state[i + 1] * 0x0E ^ state[i + 2] * 0x0B ^ state[i + 3] * 0x0D) % 256
        temp[i+2] = (state[i] * 0x0D ^ state[i + 1] * 0x09 ^ state[i + 2] * 0x0E ^ state[i + 3] * 0x0B) % 256
        temp[i+3] = (state[i] * 0x0B ^ state[i + 1] * 0x0D ^ state[i + 2] * 0x09 ^ state[i + 3] * 0x0E) % 256
    for i in range(16):
        state[i] = temp[i]

# Key expansion for AES encryption
def key_expansion(key):
    w = bytearray(16 * 11)  # 11 round keys
    for i in range(16):
        w[i] = key[i]
    for i in range(4, 44):
        temp = bytearray(4)
        for j in range(4):
            temp[j] = w[(i-1)*4 + j]
        if i % 4 == 0:
            temp = bytearray([s_box[temp[1]], s_box[temp[2]], s_box[temp[3]], s_box[temp[0]]])
            temp[0] ^= Rcon[i // 4]
        for j in range(4):
            w[i*4 + j] = w[(i-4)*4 + j] ^ temp[j]
    return w

# Add round key operation
def add_round_key(state, round_key):
    for i in range(16):
        state[i] ^= round_key[i]

# AES encryption
def aes_encrypt(input_data, key):
    state = bytearray(input_data)
    round_key = key_expansion(key)
    add_round_key(state, round_key[:16])
    for i in range(1, 10):
        sub_bytes(state)
        shift_rows(state)
        mix_columns(state)
        add_round_key(state, round_key[i*16:(i+1)*16])
    sub_bytes(state)
    shift_rows(state)
    add_round_key(state, round_key[160:])
    return state

# AES decryption
def aes_decrypt(input_data, key):
    state = bytearray(input_data)
    round_key = key_expansion(key)
    add_round_key(state, round_key[160:])
    inv_shift_rows(state)
    inv_sub_bytes(state)
    for i in range(9, 0, -1):
        add_round_key(state, round_key[i*16:(i+1)*16])
        inv_mix_columns(state)
        inv_shift_rows(state)
        inv_sub_bytes(state)
    add_round_key(state, round_key[:16])
    return state

# File encryption function
def encrypt_file(input_file, output_file, password, buffer_size):
    with open(input_file, 'rb') as f:
        plaintext = bytearray(f.read())

    # Add padding to make input length multiple of block size (16 bytes)
    padding_length = 16 - (len(plaintext) % 16)
    plaintext.extend(bytes([padding_length] * padding_length))

    # Convert password to a 16-byte key (truncate or pad with zeros)
    key = bytearray(password.encode('utf-8', 'ignore'))
    key = key[:16] + bytearray(16 - len(key))

    # Encrypt each block
    ciphertext = bytearray()
    for i in range(0, len(plaintext), buffer_size):
        block = plaintext[i:i+buffer_size]
        encrypted_block = aes_encrypt(block, key)
        ciphertext.extend(encrypted_block)

    # Write the ciphertext to the output file
    with open(output_file, 'wb') as f:
        f.write(ciphertext)

# File decryption function
# File decryption function
# File decryption function
# File decryption function
# File decryption function
# File decryption function
# File decryption function
def decrypt_file(input_file, output_file, password, buffer_size):
    with open(input_file, 'rb') as f:
        ciphertext = bytearray(f.read())

    # Convert password to a 16-byte key (truncate or pad with zeros)
    key = bytearray(password.encode('utf-8', 'ignore'))
    key = key[:16] + bytearray(16 - len(key))

    # Decrypt each block
    decrypted_data = bytearray()
    for i in range(0, len(ciphertext), 16):
        block = ciphertext[i:i+16]
        decrypted_block = aes_decrypt(block, key)
        decrypted_data.extend(decrypted_block)

    # Print the decrypted data in hexadecimal representation
    print("Decrypted data (hex):", decrypted_data.hex())

    # Try decoding the decrypted data using different encoding schemes
    try:
        decrypted_string_utf8 = decrypted_data.decode('utf-8')
        print("Decrypted data (UTF-8):", decrypted_string_utf8)
    except UnicodeDecodeError:
        print("Decoded with UTF-8: Error")

    try:
        decrypted_string_latin1 = decrypted_data.decode('latin-1')
        print("Decrypted data (Latin-1):", decrypted_string_latin1)
    except UnicodeDecodeError:
        print("Decoded with Latin-1: Error")

    # Write the decrypted data to the output file
    with open(output_file, 'wb') as f:
        f.write(decrypted_data)



# Main function
def main():
    # User input
    choice = input("Enter 'e' to encrypt or 'd' to decrypt: ")
    input_file = input("Enter the path to the input file: ")
    output_file = input("Enter the path to the output file: ")
    password = input("Enter the password: ")
    buffer_size = 512 * 1024  # 512 KB buffer size

    if choice.lower() == 'e':
        encrypt_file(input_file, output_file, password, buffer_size)
        print("File encrypted successfully!")
    elif choice.lower() == 'd':
        decrypt_file(input_file, output_file, password, buffer_size)
        print("File decrypted successfully!")
    else:
        print("Invalid choice. Please enter 'e' or 'd'.")

# Entry point of the script
if __name__ == "__main__":
    main()

# # Example usage:
# # Key generation
# key = bytearray(b'mysecretkey12345')  # Replace with your key

# # Encryption
# plaintext = bytearray(b'Hello, World!')
# encrypted_data = aes_encrypt(plaintext, key)
# print("Encrypted data:", encrypted_data)

# # Decryption
# decrypted_data = aes_decrypt(encrypted_data, key)
# print("Decrypted data:", decrypted_data.decode('utf-8').rstrip('\x00'))  # Remove null padding and decode to string