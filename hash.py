import sys

K = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
]


def generate_hash(message: bytearray) -> bytearray:
    """Return a SHA-256 hash from the message passed.
    The argument should be a bytes, bytearray, or
    string object."""

    if isinstance(message, str):
        message = bytearray(message, 'ascii')
    elif isinstance(message, bytes):
        message = bytearray(message)
    elif not isinstance(message, bytearray):
        raise TypeError

    # Добавляем дополнение к сообщению (Padding)
    length = len(message) * 8  # Длина сообщения в битах
    message.append(0x80)  # Добавляем 1 после сообщения
    while (len(message) * 8 + 64) % 512 != 0:  # Добавляем нули до кратности 512 битам
        message.append(0x00)
    message += length.to_bytes(8, 'big')  # Добавляем длину сообщения в конец

    # Разбиваем сообщение на блоки по 512 бит
    blocks = [message[i:i+64] for i in range(0, len(message), 64)]


    # Инициализируем переменные состояния хэша
    h = [
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
        0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
    ]

    # Вычисляем SHA-256 хэш
    for block in blocks:
        w = [0] * 64
        for t in range(64):
            if t < 16:
                w[t] = int.from_bytes(block[t*4:(t+1)*4], 'big')
            else:
                w[t] = (sigma1(w[t-2]) + w[t-7] + sigma0(w[t-15]) + w[t-16]) % (1 << 32)

        a, b, c, d, e, f, g, h0 = h
        for t in range(64):
            t1 = (h0 + capsigma1(e) + ch(e, f, g) + K[t] + w[t]) % (1 << 32)
            t2 = (capsigma0(a) + maj(a, b, c)) % (1 << 32)
            h0, h1, h2, h3, h4, h5, h6, h7 = (
                (t1 + t2) % (1 << 32), a, b, c, (d + t1) % (1 << 32), e, f, g
            )




# Вспомогательные функции для SHA-256
def sigma0(x):
    return _rotate_right(x, 7) ^ _rotate_right(x, 18) ^ (x >> 3)

def sigma1(x):
    return _rotate_right(x, 17) ^ _rotate_right(x, 19) ^ (x >> 10)

def capsigma0(x):
    return _rotate_right(x, 2) ^ _rotate_right(x, 13) ^ _rotate_right(x, 22)

def capsigma1(x):
    return _rotate_right(x, 6) ^ _rotate_right(x, 11) ^ _rotate_right(x, 25)



