import base64
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Random import get_random_bytes
import random
import struct
import hashlib
from typing import Optional

# ================== Класс шифрования ==================

def calculate_iterations_from_password(password: str, iterations_password: str) -> int:
    """
    Вычисляет количество итераций на основе хеша связки двух паролей.
    Если второй пароль пуст, используется только основной.
    """
    combined_password = password + iterations_password
    # Используем sha256, как в исходном коде
    hash_value = hashlib.sha256(combined_password.encode('utf-8')).digest()
    # Берем первые 4 байта для преобразования в целое число (для диапазона)
    # Используем >I для Big-endian беззнакового int (4 байта)
    hash_int = struct.unpack('>I', hash_value[:4])[0]
    
    min_iter = 5000000
    max_iter = 6000000
    
    # Детерминированное определение итераций в заданном диапазоне
    iterations = min_iter + (hash_int % (max_iter - min_iter + 1))
    return iterations

class AESGCMCipher:
    def __init__(self, password: str, iterations_password: str = ""):
        self.password = password.encode('utf-8')
        self.iterations_password = iterations_password.encode('utf-8')

    def _get_encryption_key(self, salt: bytes, iterations: int) -> bytes:
        """Получает ключ из пароля, соли и итераций."""
        # dkLen=32 для AES-256
        return PBKDF2(self.password, salt, dkLen=32, count=iterations)

    def encrypt(self, data: bytes, iterations: Optional[int] = None) -> (bytes, int):
        """
        Шифрует данные. Если итерации не заданы, использует случайное число
        или вычисляет его из пароля и пароля для итераций, если он задан.
        
        Возвращает: (зашифрованный пакет, использованное количество итераций)
        """
        salt = get_random_bytes(16)
        
        # Определяем количество итераций для шифрования
        actual_iterations = 0
        iterations_password_str = self.iterations_password.decode('utf-8')
        
        if iterations_password_str:
            # Если задан пароль для итераций, используем детерминированный расчет
            actual_iterations = calculate_iterations_from_password(
                self.password.decode('utf-8'),
                iterations_password_str
            )
        elif iterations is not None:
            # Если явно задано
            if iterations < 5000000:
                raise ValueError("Количество итераций должно быть не менее 5 000 000!")
            actual_iterations = iterations
        else:
            # Иначе - случайное, как в GUI при пустом поле
            actual_iterations = random.randint(5000000, 6000000)

        key = self._get_encryption_key(salt, actual_iterations)

        cipher = AES.new(key, AES.MODE_GCM)
        ciphertext, tag = cipher.encrypt_and_digest(data)
        
        # salt (16) + nonce (16) + ciphertext + tag (16)
        encrypted_packet = salt + cipher.nonce + ciphertext + tag
        return encrypted_packet, actual_iterations

    def decrypt(self, packet: bytes, preferred_iterations: int) -> bytes:
        """
        Расшифровывает данные, сначала пытаясь использовать preferred_iterations,
        затем - детерминированный расчет из паролей.
        
        preferred_iterations - это значение, которое было в поле 'Итерации для расшифровки'
        (по умолчанию 100000), предназначенное для быстрого теста.
        """
        try:
            salt = packet[:16]
            nonce = packet[16:32]
            ciphertext = packet[32:-16]
            tag = packet[-16:]
            
            # Попытка 1: С заданным preferred_iterations (из env или по умолчанию)
            key = self._get_encryption_key(salt, preferred_iterations)
            
            cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
            plaintext = cipher.decrypt_and_verify(ciphertext, tag)
            return plaintext
        except ValueError:
            # Попытка 2: С вычисленным детерминированным количеством итераций
            try:
                iterations = calculate_iterations_from_password(
                    self.password.decode('utf-8'),
                    self.iterations_password.decode('utf-8')
                )
                
                salt = packet[:16]
                nonce = packet[16:32]
                ciphertext = packet[32:-16]
                tag = packet[-16:]
                
                key = self._get_encryption_key(salt, iterations)

                cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
                plaintext = cipher.decrypt_and_verify(ciphertext, tag)
                return plaintext
            except ValueError as e:
                # Ни одна попытка не удалась
                raise ValueError("Ошибка расшифрования: повреждённые данные или неверный пароль") from e