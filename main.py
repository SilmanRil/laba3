import base64
from sympy import randprime
import socket

# Простейшая реализация RSA


def inverse_mod(a, m):
    m0, x0, x1 = m, 0, 1
    if m == 1:
        return 0
    while a > 1:
        q = a // m
        m, a = a % m, m
        x0, x1 = x1 - q * x0, x0
    if x1 < 0:
        x1 += m0
    return x1


def generate_rsa_keypair(p, q):
    n = p * q
    phi = (p - 1) * (q - 1)
    e = 65537  # Общее значение e
    d = inverse_mod(e, phi)
    return (e, n), (d, n)


def format_key_as_pem(key, is_private=True):
    key_type = "PRIVATE KEY" if is_private else "PUBLIC KEY"
    d_bytes = key[0].to_bytes((key[0].bit_length() + 7) // 8, 'big')
    n_bytes = key[1].to_bytes((key[1].bit_length() + 7) // 8, 'big')
    key_bytes = d_bytes + n_bytes
    key_b64 = base64.b64encode(key_bytes).decode('utf-8')
    pem = f"-----BEGIN {key_type}-----\n"
    pem += '\n'.join(key_b64[i:i + 64] for i in range(0, len(key_b64), 64))
    pem += f"\n-----END {key_type}-----\n"
    return pem

def save_key_to_file(key, path, is_private=True):
    with open(path, 'w', encoding='utf-8') as f:
        f.write(format_key_as_pem(key, is_private))

def encrypt(public_key, plaintext):
    e, n = public_key
    return pow(plaintext, e, n)


def decrypt(private_key, ciphertext):
    d, n = private_key
    return pow(ciphertext, d, n)


def generate_keys():
    p = randprime(2**511, 2**512)  # Генерация 512-битного простого числа
    q = randprime(2**511, 2**512)  # Генерация 512-битного простого числа
    public_key, private_key = generate_rsa_keypair(p, q)
    save_key_to_file(public_key, "public_key.pem", is_private=False)
    save_key_to_file(private_key, "private_key.pem", is_private=True)

def load_private_key(private_key_path):
    with open(private_key_path, "r", encoding='utf-8') as f:
        pem_data = f.readlines()
    key_b64 = ''.join(line.strip() for line in pem_data[1:-1])
    key_bytes = base64.b64decode(key_b64)

    # Изменим размеры d и n для динамического определения
    key_length = len(key_bytes) // 2
    d = int.from_bytes(key_bytes[:key_length], 'big')
    n = int.from_bytes(key_bytes[key_length:], 'big')
    return d, n

class SHA256:
    def __init__(self):
        self.h = [
            0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
            0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
        ]
        self.k = [
            0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
            0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
            0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
            0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
            0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
            0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
            0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
            0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
            0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
            0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
            0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
            0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
            0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
            0x391c0cb3, 0x4ed8aa11, 0x5b9cca4f, 0x682e6ff3,
            0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
            0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
        ]

    def _preprocess(self, message):
        original_byte_len = len(message)
        original_bit_len = original_byte_len * 8
        message += b'\x80'
        message += b'\x00' * ((56 - (original_byte_len + 1) % 64) % 64)
        message += original_bit_len.to_bytes(8, byteorder='big')
        return message

    def _rotate_right(self, n, b):
        return ((n >> b) | (n << (32 - b))) & 0xffffffff

    def _process_chunk(self, chunk):
        w = [int.from_bytes(chunk[i:i + 4], 'big') for i in range(0, 64, 4)] + [0] * 48
        for i in range(16, 64):
            s0 = self._rotate_right(w[i - 15], 7) ^ self._rotate_right(w[i - 15], 18) ^ (w[i - 15] >> 3)
            s1 = self._rotate_right(w[i - 2], 17) ^ self._rotate_right(w[i - 2], 19) ^ (w[i - 2] >> 10)
            w[i] = (w[i - 16] + s0 + w[i - 7] + s1) & 0xffffffff

        a, b, c, d, e, f, g, h = self.h

        for i in range(64):
            S1 = self._rotate_right(e, 6) ^ self._rotate_right(e, 11) ^ self._rotate_right(e, 25)
            ch = (e & f) ^ (~e & g)
            temp1 = (h + S1 + ch + self.k[i] + w[i]) & 0xffffffff
            S0 = self._rotate_right(a, 2) ^ self._rotate_right(a, 13) ^ self._rotate_right(a, 22)
            maj = (a & b) ^ (a & c) ^ (b & c)
            temp2 = (S0 + maj) & 0xffffffff

            h = g
            g = f
            f = e
            e = (d + temp1) & 0xffffffff
            d = c
            c = b
            b = a
            a = (temp1 + temp2) & 0xffffffff

        self.h[0] = (self.h[0] + a) & 0xffffffff
        self.h[1] = (self.h[1] + b) & 0xffffffff
        self.h[2] = (self.h[2] + c) & 0xffffffff
        self.h[3] = (self.h[3] + d) & 0xffffffff
        self.h[4] = (self.h[4] + e) & 0xffffffff
        self.h[5] = (self.h[5] + f) & 0xffffffff
        self.h[6] = (self.h[6] + g) & 0xffffffff
        self.h[7] = (self.h[7] + h) & 0xffffffff

    def hash(self, message):
        message = self._preprocess(message)
        for i in range(0, len(message), 64):
            self._process_chunk(message[i:i + 64])
        return b''.join(h.to_bytes(4, 'big') for h in self.h)


def simple_sha256(data):
    import hashlib
    return int(hashlib.sha256(data).hexdigest(), 16)


def sign_document(document_path, private_key_path, hash_algorithm):
    with open(document_path, "rb") as f:
        document = f.read()

    d, n = load_private_key(private_key_path)

    if hash_algorithm == "SHA256":
        hash_value = simple_sha256(document)
    else:
        raise ValueError("Неизвестный алгоритм хеширования")

    signature = pow(hash_value, d, n)

    with open("signature.txt", "wb") as f:
        f.write(base64.b64encode(signature.to_bytes((signature.bit_length() + 7) // 8, 'big')))

    # Запрос временной метки у сервера
    timestamp = request_timestamp()
    print(f"Документ успешно подписан! Штамп времени: {timestamp}")

    # Записываем время в файл
    with open("timestamp.txt", "w") as f:
        f.write(timestamp)

def request_timestamp():
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket.connect(('localhost', 5000))  # Подключаемся к серверу

    timestamp = client_socket.recv(1024).decode('utf-8')  # Получаем данные от сервера
    client_socket.close()  # Закрываем соединение

    return timestamp

def load_public_key(public_key_path):
    with open(public_key_path, "r", encoding='utf-8') as f:
        pem_data = f.readlines()
    key_b64 = ''.join(line.strip() for line in pem_data[1:-1])
    key_bytes = base64.b64decode(key_b64)
    e_size = 3
    n_size = 256
    e = int.from_bytes(key_bytes[:e_size], 'big')
    n = int.from_bytes(key_bytes[e_size:e_size + n_size], 'big')
    return (e, n)


def verify_signature(document_path, public_key_path, signature_path):
    with open(document_path, "rb") as f:
        document = f.read()

    public_key = load_public_key(public_key_path)

    hash_value = simple_sha256(document)

    with open(signature_path, "rb") as f:
        signature = int.from_bytes(base64.b64decode(f.read()), 'big')

    decrypted_hash = decrypt(public_key, signature)

    if decrypted_hash == hash_value:
        print("Подпись действительна!")

        # Читаем время из файла
        with open("timestamp.txt", "r") as f:
            timestamp = f.read().strip()

        print("Алгоритм хеширования: SHA256")
        print("Алгоритм подписи: RSA")
        print("Автор подписи: [NIKITA ZADERA]")
        print(f"Время создания подписи: {timestamp}")  # Используем время из файла
    else:
        print("Подпись недействительна.")


def main():

    while True:

        print("Выберите действие:")
        print("1. Генерация ключей")
        print("2. Подписание документа")
        print("3. Проверка подписи")
        print("4. Выход")
        choice = input("Ввод: ")

        if choice == "1":
            generate_keys()
        elif choice == "2":
            hash_algorithm = input("Выберите алгоритм хеширования (SHA256): ")
            sign_document("document.txt", "private_key.pem", hash_algorithm)
        elif choice == "3":
            verify_signature("document.txt", "public_key.pem", "signature.txt")
        elif choice == "4":
            break
        else:
            print("Неверный выбор, попробуйте снова.")


if __name__ == "__main__":
    main()