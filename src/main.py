# Реализация алгоритма AES-128 (шифрование и дешифрование)

# S-box таблица подстановок
SBOX = [
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
]

# Инверсная S-box таблица для расшифрования
INV_SBOX = [
    0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
    0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
    0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
    0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
    0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
    0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
    0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
    0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
    0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
    0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
    0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
    0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
    0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
    0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
    0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
    0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d
]

# Константы для расширения ключа
RCON = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36]

# Умножение в поле Галуа GF(2^8)
def galois_multiplication(a, b):
    p = 0
    for _ in range(8):
        if b & 1:
            p ^= a
        high_bit_set = a & 0x80
        a <<= 1
        if high_bit_set:
            a ^= 0x1b  # Полином x^8 + x^4 + x^3 + x + 1
        b >>= 1
    return p & 0xff

# Операция SubBytes: замена каждого байта значением из S-Box
def sub_bytes(state):
    for i in range(4):
        for j in range(4):
            state[i][j] = SBOX[state[i][j]]
    return state

# Операция ShiftRows: циклический сдвиг строк состояния
def shift_rows(state):
    # Первая строка не сдвигается
    # Вторая строка сдвигается на 1 байт влево
    state[1] = state[1][1:] + state[1][:1]
    # Третья строка сдвигается на 2 байта влево
    state[2] = state[2][2:] + state[2][:2]
    # Четвертая строка сдвигается на 3 байта влево
    state[3] = state[3][3:] + state[3][:3]
    return state

# Операция MixColumns: смешивание данных внутри колонок
def mix_columns(state):
    for i in range(4):
        # Сохраняем исходные значения столбца
        s0 = state[0][i]
        s1 = state[1][i]
        s2 = state[2][i]
        s3 = state[3][i]
        
        # Выполняем умножение в поле Галуа согласно спецификации AES
        state[0][i] = galois_multiplication(s0, 2) ^ galois_multiplication(s1, 3) ^ s2 ^ s3
        state[1][i] = s0 ^ galois_multiplication(s1, 2) ^ galois_multiplication(s2, 3) ^ s3
        state[2][i] = s0 ^ s1 ^ galois_multiplication(s2, 2) ^ galois_multiplication(s3, 3)
        state[3][i] = galois_multiplication(s0, 3) ^ s1 ^ s2 ^ galois_multiplication(s3, 2)
    
    return state

# Операция AddRoundKey: добавление раундового ключа через XOR
def add_round_key(state, round_key):
    for i in range(4):
        for j in range(4):
            state[i][j] ^= round_key[i][j]
    return state

# Операция InvSubBytes: обратная замена байт для расшифрования
def inv_sub_bytes(state):
    for i in range(4):
        for j in range(4):
            state[i][j] = INV_SBOX[state[i][j]]
    return state

# Операция InvShiftRows: обратный циклический сдвиг строк
def inv_shift_rows(state):
    # Первая строка не сдвигается
    # Вторая строка сдвигается на 1 байт вправо
    state[1] = state[1][-1:] + state[1][:-1]
    # Третья строка сдвигается на 2 байта вправо
    state[2] = state[2][-2:] + state[2][:-2]
    # Четвертая строка сдвигается на 3 байта вправо
    state[3] = state[3][-3:] + state[3][:-3]
    return state

# Операция InvMixColumns: обратное преобразование MixColumns
def inv_mix_columns(state):
    for i in range(4):
        s0 = state[0][i]
        s1 = state[1][i]
        s2 = state[2][i]
        s3 = state[3][i]
        
        state[0][i] = galois_multiplication(s0, 0x0e) ^ galois_multiplication(s1, 0x0b) ^ \
                      galois_multiplication(s2, 0x0d) ^ galois_multiplication(s3, 0x09)
        state[1][i] = galois_multiplication(s0, 0x09) ^ galois_multiplication(s1, 0x0e) ^ \
                      galois_multiplication(s2, 0x0b) ^ galois_multiplication(s3, 0x0d)
        state[2][i] = galois_multiplication(s0, 0x0d) ^ galois_multiplication(s1, 0x09) ^ \
                      galois_multiplication(s2, 0x0e) ^ galois_multiplication(s3, 0x0b)
        state[3][i] = galois_multiplication(s0, 0x0b) ^ galois_multiplication(s1, 0x0d) ^ \
                      galois_multiplication(s2, 0x09) ^ galois_multiplication(s3, 0x0e)
    
    return state

# Расширение ключа для генерации раундовых ключей
def key_expansion(key):
    # Преобразуем ключ из 16 байт в матрицу 4x4
    key_matrix = [list(key[i:i+4]) for i in range(0, 16, 4)]
    key_matrix = [[key_matrix[j][i] for j in range(4)] for i in range(4)]
    
    # Генерируем 11 ключей для 10 раундов + начальное состояние
    round_keys = [key_matrix]
    
    # Расширяем ключ
    for i in range(10):
        # Берем предыдущий ключ
        prev_key = round_keys[-1]
        new_key = [[0 for _ in range(4)] for _ in range(4)]
        
        # Берем последний столбец и выполняем RotWord операцию
        temp = [prev_key[1][3], prev_key[2][3], prev_key[3][3], prev_key[0][3]]
        
        # Применяем SubBytes
        temp = [SBOX[byte] for byte in temp]
        
        # XOR с первым столбцом предыдущего ключа и с RCON
        new_key[0][0] = prev_key[0][0] ^ temp[0] ^ RCON[i]
        new_key[1][0] = prev_key[1][0] ^ temp[1]
        new_key[2][0] = prev_key[2][0] ^ temp[2]
        new_key[3][0] = prev_key[3][0] ^ temp[3]
        
        # Вычисляем остальные столбцы
        for j in range(1, 4):
            for k in range(4):
                new_key[k][j] = prev_key[k][j] ^ new_key[k][j-1]
        
        round_keys.append(new_key)
    
    return round_keys

# Преобразование байтового массива в матрицу состояния
def bytes_to_state(data):
    state = [[0 for _ in range(4)] for _ in range(4)]
    for i in range(4):
        for j in range(4):
            state[j][i] = data[i * 4 + j]
    return state

# Преобразование матрицы состояния в байтовый массив
def state_to_bytes(state):
    data = bytearray(16)
    for i in range(4):
        for j in range(4):
            data[i * 4 + j] = state[j][i]
    return data

# Функция шифрования блока данных (16 байт)
def aes_encrypt_block(data, key):
    # Проверка длины ключа и блока данных
    if len(key) != 16:
        raise ValueError("Ключ должен быть длиной 16 байт (128 бит)")
    if len(data) != 16:
        raise ValueError("Блок данных должен быть длиной 16 байт (128 бит)")
    
    # Генерируем расширенный ключ
    round_keys = key_expansion(key)
    
    # Преобразуем данные в матрицу состояния
    state = bytes_to_state(data)
    
    # Начальное добавление ключа
    state = add_round_key(state, round_keys[0])
    
    # 9 основных раундов
    for i in range(1, 10):
        state = sub_bytes(state)
        state = shift_rows(state)
        state = mix_columns(state)
        state = add_round_key(state, round_keys[i])
    
    # Финальный раунд (без MixColumns)
    state = sub_bytes(state)
    state = shift_rows(state)
    state = add_round_key(state, round_keys[10])
    
    # Преобразование матрицы состояния обратно в байтовый массив
    return state_to_bytes(state)

# Функция расшифрования блока данных (16 байт)
def aes_decrypt_block(ciphertext, key):
    # Проверка длины ключа и блока данных
    if len(key) != 16:
        raise ValueError("Ключ должен быть длиной 16 байт (128 бит)")
    if len(ciphertext) != 16:
        raise ValueError("Блок данных должен быть длиной 16 байт (128 бит)")
    
    # Генерируем расширенный ключ
    round_keys = key_expansion(key)
    
    # Преобразуем данные в матрицу состояния
    state = bytes_to_state(ciphertext)
    
    # Начальное добавление последнего ключа
    state = add_round_key(state, round_keys[10])
    
    # 9 основных раундов в обратном порядке
    for i in range(9, 0, -1):
        state = inv_shift_rows(state)
        state = inv_sub_bytes(state)
        state = add_round_key(state, round_keys[i])
        state = inv_mix_columns(state)
    
    # Финальный раунд
    state = inv_shift_rows(state)
    state = inv_sub_bytes(state)
    state = add_round_key(state, round_keys[0])
    
    # Преобразование матрицы состояния обратно в байтовый массив
    return state_to_bytes(state)

# Функция шифрования данных произвольной длины (с PKCS#7 padding)
def aes_encrypt(data, key, iv=None):
    # Добавляем padding по стандарту PKCS#7
    padding_length = 16 - (len(data) % 16)
    padding = bytes([padding_length]) * padding_length
    padded_data = data + padding
    
    # Для режима CBC нужен вектор инициализации
    if iv is None:
        # Если IV не указан, используем нулевой вектор
        iv = bytes(16)
    
    result = bytearray()
    prev_block = iv
    
    # Разбиваем данные на блоки по 16 байт
    for i in range(0, len(padded_data), 16):
        # Преобразуем в bytearray для возможности изменения
        block = bytearray(padded_data[i:i+16])
        
        # Режим CBC: XOR с предыдущим блоком шифротекста
        for j in range(16):
            block[j] ^= prev_block[j]
        
        # Шифруем блок
        encrypted_block = aes_encrypt_block(bytes(block), key)
        result.extend(encrypted_block)
        
        # Сохраняем текущий блок шифротекста для следующей итерации
        prev_block = encrypted_block
    
    return bytes(result)

# Функция расшифрования данных произвольной длины (с обработкой PKCS#7 padding)
def aes_decrypt(ciphertext, key, iv=None):
    if len(ciphertext) % 16 != 0:
        raise ValueError("Длина шифротекста должна быть кратной 16 байтам")
    
    # Для режима CBC нужен вектор инициализации
    if iv is None:
        # Если IV не указан, используем нулевой вектор
        iv = bytes(16)
    
    result = bytearray()
    prev_block = iv
    
    # Разбиваем данные на блоки по 16 байт
    for i in range(0, len(ciphertext), 16):
        block = ciphertext[i:i+16]
        
        # Расшифровываем блок
        decrypted_block = bytearray(aes_decrypt_block(block, key))
        
        # Режим CBC: XOR с предыдущим блоком шифротекста
        for j in range(16):
            decrypted_block[j] ^= prev_block[j]
        
        result.extend(decrypted_block)
        
        # Сохраняем текущий блок шифротекста для следующей итерации
        prev_block = block
    
    # Удаляем padding
    padding_length = result[-1]
    if padding_length > 0 and padding_length <= 16:
        # Проверяем, что padding корректный
        for i in range(1, padding_length + 1):
            if result[-i] != padding_length:
                break
        else:
            # Удаляем padding, только если он корректный
            result = result[:-padding_length]
    
    return bytes(result)

import subprocess
import tempfile
import os

def verify_with_openssl(plaintext, key, iv):
    """Проверяет шифрование и расшифрование с помощью OpenSSL"""
    # Создаем временные файлы
    with tempfile.NamedTemporaryFile(delete=False) as plaintext_file:
        plaintext_file.write(plaintext)
        plaintext_path = plaintext_file.name
    
    ciphertext_path = tempfile.mktemp()
    decrypted_path = tempfile.mktemp()
    
    try:
        # Формируем ключ и IV в шестнадцатеричном формате
        key_hex = ''.join(f'{b:02x}' for b in key)
        iv_hex = ''.join(f'{b:02x}' for b in iv)
        
        # Шифруем с помощью OpenSSL
        enc_cmd = f'openssl enc -aes-128-cbc -e -in {plaintext_path} -out {ciphertext_path} -K {key_hex} -iv {iv_hex}'
        subprocess.run(enc_cmd, shell=True, check=True)
        
        # Расшифровываем с помощью OpenSSL
        dec_cmd = f'openssl enc -aes-128-cbc -d -in {ciphertext_path} -out {decrypted_path} -K {key_hex} -iv {iv_hex}'
        subprocess.run(dec_cmd, shell=True, check=True)
        
        # Читаем результаты
        with open(ciphertext_path, 'rb') as f:
            openssl_ciphertext = f.read()
        
        with open(decrypted_path, 'rb') as f:
            openssl_decrypted = f.read()
        
        return True, openssl_ciphertext, openssl_decrypted
    
    except Exception as e:
        print(f"Ошибка при проверке с OpenSSL: {e}")
        return False, None, None
    
    finally:
        # Удаляем временные файлы
        os.unlink(plaintext_path)
        if os.path.exists(ciphertext_path):
            os.unlink(ciphertext_path)
        if os.path.exists(decrypted_path):
            os.unlink(decrypted_path)

# Пример использования
if __name__ == "__main__":
    # Импортируем и запускаем GUI, если это основной скрипт
    try:
        from gui import AES128App
        app = AES128App()
        app.mainloop()
    except ImportError:
        # Если GUI не найден, запустим демонстрационный пример в консоли
        # Ключ 128 бит (16 байт)
        key = b"MySecretKey12345"
        
        # Вектор инициализации (для режима CBC)
        iv = b"InitVectorAES128"
        
        # Исходные данные для шифрования
        plaintext = b"This is a secret message that needs to be encrypted using AES-128."
        
        print("Оригинальный текст:", plaintext.decode())
        
        # Шифрование
        ciphertext = aes_encrypt(plaintext, key, iv)
        print("\nШифротекст (в шестнадцатеричном виде):", ciphertext.hex())
        
        # Расшифрование
        decrypted = aes_decrypt(ciphertext, key, iv)
        print("\nРасшифрованный текст:", decrypted.decode())
        
        # Проверка
        print("\nРезультат проверки:", "Успешно" if plaintext == decrypted else "Ошибка")
        
        # Проверка с помощью OpenSSL
        print("\n--- Проверка с помощью OpenSSL ---")
        success, openssl_ciphertext, openssl_decrypted = verify_with_openssl(plaintext, key, iv)
        
        if success:
            print("OpenSSL шифрование/расшифрование успешно выполнено.")
            print("\nСравнение с нашей реализацией:")
            
            # Сравниваем результаты шифрования
            if openssl_ciphertext == ciphertext:
                print("- Шифротексты совпадают: ДА")
            else:
                print("- Шифротексты совпадают: НЕТ")
                print("  OpenSSL шифротекст:", openssl_ciphertext.hex())
                print("  Наш шифротекст:    ", ciphertext.hex())
            
            # Сравниваем результаты расшифрования
            if openssl_decrypted == plaintext:
                print("- Результаты расшифрования совпадают с исходным текстом: ДА")
            else:
                print("- Результаты расшифрования совпадают с исходным текстом: НЕТ")
        else:
            print("Не удалось выполнить проверку с OpenSSL. Убедитесь, что OpenSSL установлен и доступен в системе.")