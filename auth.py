# auth.py
import psycopg2
import time
import os


class CustomRandom:
    """Собственный генератор случайных чисел"""

    def __init__(self):
        self.seed = int(time.time() * 1000000) + os.getpid()

    def _generate_random_bits(self, num_bits):
        """Генерация случайных битов на основе времени и PID"""
        result = 0
        for i in range(num_bits):
            self.seed = (self.seed * 1103515245 + 12345) & 0x7fffffff
            bit = (self.seed >> 16) & 1
            result = (result << 1) | bit
        return result

    def token_hex(self, num_bytes):
        """Генерация hex строки заданной длины"""
        hex_chars = "0123456789abcdef"
        result = []
        for _ in range(num_bytes):
            random_bits = self._generate_random_bits(8)
            byte_val = random_bits & 0xFF
            result.append(hex_chars[byte_val >> 4])
            result.append(hex_chars[byte_val & 0x0F])
        return ''.join(result)


class CustomPacker:
    """Собственная реализация упаковки/распаковки данных"""

    @staticmethod
    def pack_big_endian_64bit(value):
        """Упаковка 64-битного числа в big-endian формат"""
        result = bytearray(8)
        for i in range(7, -1, -1):
            result[i] = value & 0xFF
            value >>= 8
        return bytes(result)

    @staticmethod
    def unpack_big_endian_32bit(data):
        """Распаковка 32-битного числа из big-endian формата"""
        if len(data) < 4:
            return 0
        value = 0
        for i in range(4):
            value = (value << 8) | data[i]
        return value & 0xFFFFFFFF


class CustomHasher:
    """Класс для собственной реализации хеширования"""

    def __init__(self):
        self.random = CustomRandom()
        self.packer = CustomPacker()

    @staticmethod
    def _rotate_left(n, b):
        """Циклический сдвиг влево"""
        return ((n << b) | (n >> (32 - b))) & 0xffffffff

    @staticmethod
    def _rotate_right(n, b):
        """Циклический сдвиг вправо"""
        return ((n >> b) | (n << (32 - b))) & 0xffffffff

    def _pad_message(self, message):
        """Добавление padding к сообщению по стандарту SHA-256"""
        # Конвертируем строку в байты если нужно
        if isinstance(message, str):
            message = self._string_to_bytes(message)

        original_length = len(message)
        bit_length = original_length * 8

        # Добавляем бит '1'
        message += b'\x80'

        # Добавляем нули пока длина не станет ≡ 56 (mod 64)
        while (len(message) % 64) != 56:
            message += b'\x00'

        # Добавляем длину оригинального сообщения в битах (64 бита, big-endian)
        message += self.packer.pack_big_endian_64bit(bit_length)

        return message

    def _string_to_bytes(self, s):
        """Конвертация строки в байты"""
        return bytes(s, 'utf-8')

    def _chunk_message(self, message, chunk_size=64):
        """Разделение сообщения на chunks по 64 байта"""
        chunks = []
        for i in range(0, len(message), chunk_size):
            chunks.append(message[i:i + chunk_size])
        return chunks

    def custom_sha256(self, message):
        """
        Собственная реализация SHA-256
        """
        # Инициализация хеш-значений (первые 32 бита дробных частей кубических корней первых 8 простых чисел)
        h = [
            0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
            0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
        ]

        # Константы раундов (первые 32 бита дробных частей кубических корней первых 64 простых чисел)
        k = [
            0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
            0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
            0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
            0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
            0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
            0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
            0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
            0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
        ]

        # Подготовка сообщения
        message = self._pad_message(message)
        chunks = self._chunk_message(message)

        for chunk in chunks:
            # Рабочий массив
            w = [0] * 64

            # Копируем chunk в первые 16 слов
            for i in range(16):
                w[i] = self.packer.unpack_big_endian_32bit(chunk[i * 4:(i + 1) * 4])

            # Расширяем остальные 48 слов
            for i in range(16, 64):
                s0 = self._rotate_right(w[i - 15], 7) ^ self._rotate_right(w[i - 15], 18) ^ (w[i - 15] >> 3)
                s1 = self._rotate_right(w[i - 2], 17) ^ self._rotate_right(w[i - 2], 19) ^ (w[i - 2] >> 10)
                w[i] = (w[i - 16] + s0 + w[i - 7] + s1) & 0xffffffff

            # Инициализация рабочих переменных
            a, b, c, d, e, f, g, h_temp = h

            # Основной цикл
            for i in range(64):
                s1 = self._rotate_right(e, 6) ^ self._rotate_right(e, 11) ^ self._rotate_right(e, 25)
                ch = (e & f) ^ ((~e) & g)
                temp1 = (h_temp + s1 + ch + k[i] + w[i]) & 0xffffffff
                s0 = self._rotate_right(a, 2) ^ self._rotate_right(a, 13) ^ self._rotate_right(a, 22)
                maj = (a & b) ^ (a & c) ^ (b & c)
                temp2 = (s0 + maj) & 0xffffffff

                h_temp = g
                g = f
                f = e
                e = (d + temp1) & 0xffffffff
                d = c
                c = b
                b = a
                a = (temp1 + temp2) & 0xffffffff

            # Добавляем compressed chunk к текущему hash value
            h[0] = (h[0] + a) & 0xffffffff
            h[1] = (h[1] + b) & 0xffffffff
            h[2] = (h[2] + c) & 0xffffffff
            h[3] = (h[3] + d) & 0xffffffff
            h[4] = (h[4] + e) & 0xffffffff
            h[5] = (h[5] + f) & 0xffffffff
            h[6] = (h[6] + g) & 0xffffffff
            h[7] = (h[7] + h_temp) & 0xffffffff

        # Производим final hash value (big-endian)
        hash_parts = []
        for x in h:
            hash_parts.append('{:08x}'.format(x))
        return ''.join(hash_parts)


class AuthManager:
    def __init__(self, db_config):
        self.db_config = db_config
        self.hasher = CustomHasher()

    def generate_salt(self):
        """Генерация случайной соли с использованием собственного генератора"""
        return self.hasher.random.token_hex(32)  # 64 hex символа = 32 байта

    def custom_hash_password(self, password, salt=None):
        """
        Собственная функция хеширования пароля
        Использует многократное хеширование с солью для увеличения сложности
        """
        if salt is None:
            salt = self.generate_salt()

        # Многократное хеширование для увеличения сложности
        # Первый проход: пароль + соль
        hash1 = self.hasher.custom_sha256(password + salt)

        # Второй проход: первый хеш + перевернутая соль
        reversed_salt = salt[::-1]
        hash2 = self.hasher.custom_sha256(hash1 + reversed_salt)

        # Третий проход: второй хеш + соль в верхнем регистре
        upper_salt = salt.upper()
        hash3 = self.hasher.custom_sha256(hash2 + upper_salt)

        # Четвертый проход: третий хеш + соль в нижнем регистре
        lower_salt = salt.lower()
        hash4 = self.hasher.custom_sha256(hash3 + lower_salt)

        # Пятый проход: четвертый хеш + оригинальная соль (финальный хеш)
        final_hash = self.hasher.custom_sha256(hash4 + salt)

        return (final_hash, salt)

    def verify_password(self, password, hashed_password, salt):
        """Проверка пароля с использованием собственной функции хеширования"""
        test_hash, _ = self.custom_hash_password(password, salt)
        return test_hash == hashed_password

    def register_user(self, username, password, full_name):
        """
        Регистрация нового пользователя
        """
        if not username or not password or not full_name:
            return {
                'success': False,
                'message': "All fields are required"
            }

        # Проверяем, существует ли пользователь
        existing_user = self._get_user_by_username(username)
        if existing_user:
            return {
                'success': False,
                'message': "Username already exists"
            }

        # Хешируем пароль с использованием собственной функции
        password_hash, salt = self.custom_hash_password(password)

        try:
            conn = psycopg2.connect(**self.db_config)
            cur = conn.cursor()

            cur.execute(
                "INSERT INTO users (username, password_hash, salt, full_name) VALUES (%s, %s, %s, %s)",
                (username, password_hash, salt, full_name)
            )

            conn.commit()
            cur.close()
            conn.close()

            return {
                'success': True,
                'message': "User registered successfully!"
            }

        except psycopg2.Error as e:
            return {
                'success': False,
                'message': "Database error: " + str(e)
            }
        except Exception as e:
            return {
                'success': False,
                'message': "Unexpected error: " + str(e)
            }

    def login_user(self, username, password):
        """
        Аутентификация пользователя
        """
        if not username or not password:
            return {
                'success': False,
                'message': "Please enter username and password"
            }

        user_data = self._get_user_by_username(username)
        if not user_data:
            return {
                'success': False,
                'message': "Invalid username or password"
            }

        user_id, stored_username, stored_hash, salt, full_name = user_data

        if self.verify_password(password, stored_hash, salt):
            return {
                'success': True,
                'user_id': user_id,
                'username': stored_username,
                'full_name': full_name,
                'message': "Login successful"
            }
        else:
            return {
                'success': False,
                'message': "Invalid username or password"
            }

    def _get_user_by_username(self, username):
        """
        Получение данных пользователя по имени
        """
        try:
            conn = psycopg2.connect(**self.db_config)
            cur = conn.cursor()

            cur.execute(
                "SELECT user_id, username, password_hash, salt, full_name FROM users WHERE username = %s",
                (username,)
            )

            result = cur.fetchone()
            cur.close()
            conn.close()

            return result

        except psycopg2.Error as e:
            print("Database error in _get_user_by_username: " + str(e))
            return None
        except Exception as e:
            print("Unexpected error in _get_user_by_username: " + str(e))
            return None

    def change_password(self, user_id, current_password, new_password):
        """Смена пароля пользователя"""
        try:
            conn = psycopg2.connect(**self.db_config)
            cur = conn.cursor()

            cur.execute(
                "SELECT password_hash, salt FROM users WHERE user_id = %s",
                (user_id,)
            )

            result = cur.fetchone()
            if not result:
                return {
                    'success': False,
                    'message': "User not found"
                }

            stored_hash, salt = result

            if not self.verify_password(current_password, stored_hash, salt):
                return {
                    'success': False,
                    'message': "Current password is incorrect"
                }

            new_hash, new_salt = self.custom_hash_password(new_password)

            cur.execute(
                "UPDATE users SET password_hash = %s, salt = %s WHERE user_id = %s",
                (new_hash, new_salt, user_id)
            )

            conn.commit()
            cur.close()
            conn.close()

            return {
                'success': True,
                'message': "Password changed successfully"
            }

        except psycopg2.Error as e:
            return {
                'success': False,
                'message': "Database error: " + str(e)
            }

    def validate_password_strength(self, password):
        """Проверка сложности пароля"""
        if len(password) < 8:
            return {
                'valid': False,
                'message': "Password must be at least 8 characters long"
            }

        if not any(char.isdigit() for char in password):
            return {
                'valid': False,
                'message': "Password must contain at least one digit"
            }

        if not any(char.isupper() for char in password):
            return {
                'valid': False,
                'message': "Password must contain at least one uppercase letter"
            }

        if not any(char.islower() for char in password):
            return {
                'valid': False,
                'message': "Password must contain at least one lowercase letter"
            }

        special_chars = "!@#$%^&*()_+-=[]{}|;:,.<>?"
        if not any(char in special_chars for char in password):
            return {
                'valid': True,
                'message': "Consider adding special characters for better security"
            }

        return {
            'valid': True,
            'message': "Password strength is good"
        }


class AuthError(Exception):
    """Кастомное исключение для ошибок аутентификации"""
    pass