# file_manager.py
import os


class FileManager:
    def __init__(self):
        from auth import CustomHasher
        self.hasher = CustomHasher()

    def calculate_file_hash(self, file_data):
        """Вычисление хеша файла с использованием собственной функции"""
        return self.hasher.custom_sha256(file_data)

    @staticmethod
    def read_file(file_path):
        """Чтение файла в бинарном режиме"""
        with open(file_path, 'rb') as f:
            return f.read()

    @staticmethod
    def save_file(file_data, save_path):
        """Сохранение файла в бинарном режиме"""
        with open(save_path, 'wb') as f:
            f.write(file_data)

    @staticmethod
    def get_file_info(file_path):
        """Получение информации о файле"""
        file_name = os.path.basename(file_path)
        file_size = os.path.getsize(file_path)
        return file_name, file_size