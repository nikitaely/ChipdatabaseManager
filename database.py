# database.py
import psycopg2


class DatabaseManager:
    def __init__(self, db_config):
        self.db_config = db_config

    def execute_query(self, query, params=None, fetch=False):
        """
        Универсальный метод выполнения запросов к БД
        """
        try:
            conn = psycopg2.connect(**self.db_config)
            cur = conn.cursor()

            if params:
                cur.execute(query, params)
            else:
                cur.execute(query)

            if fetch:
                result = cur.fetchall()
            else:
                conn.commit()
                result = None

            cur.close()
            conn.close()
            return result

        except psycopg2.Error as e:
            raise DatabaseError("Database error: " + str(e))
        except Exception as e:
            raise DatabaseError("Unexpected error: " + str(e))

    def setup_tables(self):
        """Создание всех необходимых таблиц если их нет"""
        try:
            conn = psycopg2.connect(**self.db_config)
            cur = conn.cursor()

            # Создание таблицы users если не существует
            cur.execute('''
                CREATE TABLE IF NOT EXISTS users (
                    user_id SERIAL PRIMARY KEY,
                    username VARCHAR(255) UNIQUE NOT NULL,
                    password_hash VARCHAR(255) NOT NULL,
                    salt VARCHAR(255) NOT NULL,
                    full_name VARCHAR(255),
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            ''')

            # Создание таблицы chips если не существует
            cur.execute('''
                CREATE TABLE IF NOT EXISTS chips (
                    chip_id SERIAL PRIMARY KEY,
                    chip_number VARCHAR(255) NOT NULL,
                    description VARCHAR(255),
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            ''')

            # Создание таблицы layers если не существует
            cur.execute('''
                CREATE TABLE IF NOT EXISTS layers (
                    layer_id SERIAL PRIMARY KEY,
                    chip_id INTEGER REFERENCES chips(chip_id) ON DELETE CASCADE,
                    layer_name VARCHAR(255) NOT NULL,
                    file_extension VARCHAR(50),
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    UNIQUE(chip_id, layer_name)
                )
            ''')

            # Создание таблицы layer_versions если не существует
            cur.execute('''
                CREATE TABLE IF NOT EXISTS layer_versions (
                    version_id SERIAL PRIMARY KEY,
                    layer_id INTEGER REFERENCES layers(layer_id) ON DELETE CASCADE,
                    version_number INTEGER NOT NULL,
                    uploaded_by INTEGER REFERENCES users(user_id),
                    uploaded_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    comment VARCHAR(255),
                    file_name VARCHAR(255),
                    file_data BYTEA,
                    file_size INTEGER,
                    file_hash VARCHAR(255),
                    mime_type VARCHAR(100),
                    gds_library_name VARCHAR(255),
                    gds_mod_time TIMESTAMP,
                    gds_units NUMERIC,
                    UNIQUE(layer_id, version_number)
                )
            ''')

            # Создание индексов для улучшения производительности
            cur.execute('''
                CREATE INDEX IF NOT EXISTS idx_layers_chip_id ON layers(chip_id)
            ''')
            cur.execute('''
                CREATE INDEX IF NOT EXISTS idx_layer_versions_layer_id ON layer_versions(layer_id)
            ''')
            cur.execute('''
                CREATE INDEX IF NOT EXISTS idx_layer_versions_uploaded_by ON layer_versions(uploaded_by)
            ''')
            cur.execute('''
                CREATE INDEX IF NOT EXISTS idx_users_username ON users(username)
            ''')

            conn.commit()
            cur.close()
            conn.close()
            print("Database setup completed successfully")

        except psycopg2.Error as e:
            raise DatabaseError("Failed to setup database: " + str(e))

    # МЕТОДЫ ДЛЯ РАБОТЫ С ЧИПАМИ

    def add_chip(self, chip_number, description):
        """Добавление нового чипа"""
        return self.execute_query(
            "INSERT INTO chips (chip_number, description) VALUES (%s, %s)",
            (chip_number, description)
        )

    def get_all_chips(self):
        """Получение всех чипов"""
        results = self.execute_query(
            "SELECT chip_id, chip_number, description, created_at FROM chips ORDER BY created_at DESC",
            fetch=True
        )

        chips = []
        for row in results:
            chips.append({
                'chip_id': row[0],
                'chip_number': row[1],
                'description': row[2],
                'created_at': row[3]
            })
        return chips

    def get_chip_by_id(self, chip_id):
        """Получение чипа по ID"""
        result = self.execute_query(
            "SELECT chip_id, chip_number, description, created_at FROM chips WHERE chip_id = %s",
            (chip_id,),
            fetch=True
        )

        if result and len(result) > 0:
            row = result[0]
            return {
                'chip_id': row[0],
                'chip_number': row[1],
                'description': row[2],
                'created_at': row[3]
            }
        return None

    def update_chip(self, chip_id, chip_number=None, description=None):
        """Обновление информации о чипе"""
        updates = []
        params = []

        if chip_number is not None:
            updates.append("chip_number = %s")
            params.append(chip_number)

        if description is not None:
            updates.append("description = %s")
            params.append(description)

        if not updates:
            return None

        params.append(chip_id)
        query = "UPDATE chips SET " + ", ".join(updates) + " WHERE chip_id = %s"

        return self.execute_query(query, params)

    def delete_chip(self, chip_id):
        """Удаление чипа (каскадное удаление слоев и версий)"""
        return self.execute_query(
            "DELETE FROM chips WHERE chip_id = %s",
            (chip_id,)
        )

    def chip_exists(self, chip_number):
        """Проверка существования чипа с таким номером"""
        result = self.execute_query(
            "SELECT chip_id FROM chips WHERE chip_number = %s",
            (chip_number,),
            fetch=True
        )
        return len(result) > 0

    # МЕТОДЫ ДЛЯ РАБОТЫ СО СЛОЯМИ

    def add_layer(self, chip_id, layer_name, file_extension):
        """Добавление нового слоя"""
        return self.execute_query(
            "INSERT INTO layers (chip_id, layer_name, file_extension) VALUES (%s, %s, %s)",
            (chip_id, layer_name, file_extension)
        )

    def get_all_layers_with_chips(self):
        """Получение всех слоев с информацией о чипах"""
        results = self.execute_query('''
            SELECT l.layer_id, l.chip_id, c.chip_number, l.layer_name, l.file_extension, l.created_at 
            FROM layers l 
            JOIN chips c ON l.chip_id = c.chip_id 
            ORDER BY c.chip_number, l.layer_name
        ''', fetch=True)

        layers = []
        for row in results:
            layers.append({
                'layer_id': row[0],
                'chip_id': row[1],
                'chip_number': row[2],
                'layer_name': row[3],
                'file_extension': row[4],
                'created_at': row[5]
            })
        return layers

    def get_layers_by_chip_id(self, chip_id):
        """Получение слоев по ID чипа"""
        results = self.execute_query(
            "SELECT layer_id, layer_name, file_extension, created_at FROM layers WHERE chip_id = %s ORDER BY layer_name",
            (chip_id,),
            fetch=True
        )

        layers = []
        for row in results:
            layers.append({
                'layer_id': row[0],
                'layer_name': row[1],
                'file_extension': row[2],
                'created_at': row[3]
            })
        return layers

    def get_layer_by_id(self, layer_id):
        """Получение слоя по ID"""
        result = self.execute_query(
            "SELECT layer_id, chip_id, layer_name, file_extension, created_at FROM layers WHERE layer_id = %s",
            (layer_id,),
            fetch=True
        )

        if result and len(result) > 0:
            row = result[0]
            return {
                'layer_id': row[0],
                'chip_id': row[1],
                'layer_name': row[2],
                'file_extension': row[3],
                'created_at': row[4]
            }
        return None

    def update_layer(self, layer_id, layer_name=None, file_extension=None):
        """Обновление информации о слое"""
        updates = []
        params = []

        if layer_name is not None:
            updates.append("layer_name = %s")
            params.append(layer_name)

        if file_extension is not None:
            updates.append("file_extension = %s")
            params.append(file_extension)

        if not updates:
            return None

        params.append(layer_id)
        query = "UPDATE layers SET " + ", ".join(updates) + " WHERE layer_id = %s"

        return self.execute_query(query, params)

    def delete_layer(self, layer_id):
        """Удаление слоя (каскадное удаление версий)"""
        return self.execute_query(
            "DELETE FROM layers WHERE layer_id = %s",
            (layer_id,)
        )

    def layer_exists(self, chip_id, layer_name):
        """Проверка существования слоя с таким именем в чипе"""
        result = self.execute_query(
            "SELECT layer_id FROM layers WHERE chip_id = %s AND layer_name = %s",
            (chip_id, layer_name),
            fetch=True
        )
        return len(result) > 0

    # МЕТОДЫ ДЛЯ РАБОТЫ С ВЕРСИЯМИ

    def add_version(self, layer_id, user_id, file_data, comment, file_name, gds_library_name=None):
        """Добавление новой версии файла"""
        # Получаем номер следующей версии
        result = self.execute_query(
            "SELECT COALESCE(MAX(version_number), 0) + 1 FROM layer_versions WHERE layer_id = %s",
            (layer_id,),
            fetch=True
        )

        if result and result[0]:
            version_number = result[0][0]
        else:
            version_number = 1

        file_size = len(file_data)

        # Используем нашу собственную функцию хеширования вместо hashlib
        from auth import CustomHasher
        hasher = CustomHasher()
        file_hash = hasher.custom_sha256(file_data)

        return self.execute_query('''
            INSERT INTO layer_versions 
            (layer_id, version_number, uploaded_by, comment, file_name, file_data, file_size, file_hash, mime_type, gds_library_name) 
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
        ''', (
            layer_id, version_number, user_id, comment,
            file_name, psycopg2.Binary(file_data), file_size, file_hash,
            'application/octet-stream', gds_library_name
        ))

    def get_all_versions(self):
        """Получение всех версий с полной информацией"""
        results = self.execute_query('''
            SELECT 
                lv.version_id, 
                lv.layer_id,
                c.chip_number || ' - ' || l.layer_name as layer_display,
                lv.version_number, 
                u.username,
                u.full_name,
                lv.comment, 
                lv.file_name, 
                lv.file_size,
                lv.uploaded_at,
                lv.gds_library_name
            FROM layer_versions lv
            JOIN layers l ON lv.layer_id = l.layer_id
            JOIN chips c ON l.chip_id = c.chip_id
            JOIN users u ON lv.uploaded_by = u.user_id
            ORDER BY lv.uploaded_at DESC
        ''', fetch=True)

        versions = []
        for row in results:
            versions.append({
                'version_id': row[0],
                'layer_id': row[1],
                'layer_display': row[2],
                'version_number': row[3],
                'username': row[4],
                'full_name': row[5],
                'comment': row[6],
                'file_name': row[7],
                'file_size': row[8],
                'uploaded_at': row[9],
                'gds_library_name': row[10]
            })
        return versions

    def get_versions_by_layer_id(self, layer_id):
        """Получение версий по ID слоя"""
        results = self.execute_query('''
            SELECT 
                lv.version_id,
                lv.version_number,
                u.username,
                lv.comment,
                lv.file_name,
                lv.file_size,
                lv.uploaded_at,
                lv.gds_library_name
            FROM layer_versions lv
            JOIN users u ON lv.uploaded_by = u.user_id
            WHERE lv.layer_id = %s
            ORDER BY lv.version_number DESC
        ''', (layer_id,), fetch=True)

        versions = []
        for row in results:
            versions.append({
                'version_id': row[0],
                'version_number': row[1],
                'username': row[2],
                'comment': row[3],
                'file_name': row[4],
                'file_size': row[5],
                'uploaded_at': row[6],
                'gds_library_name': row[7]
            })
        return versions

    def get_version_data(self, version_id):
        """Получение данных файла версии"""
        result = self.execute_query(
            "SELECT file_data, file_name, file_size FROM layer_versions WHERE version_id = %s",
            (version_id,),
            fetch=True
        )

        if result and len(result) > 0:
            row = result[0]
            return {
                'file_data': row[0],
                'file_name': row[1],
                'file_size': row[2]
            }
        return None

    def get_version_info(self, version_id):
        """Получение информации о версии (без данных файла)"""
        result = self.execute_query('''
            SELECT 
                lv.version_id,
                lv.layer_id,
                c.chip_number,
                l.layer_name,
                lv.version_number,
                u.username,
                lv.comment,
                lv.file_name,
                lv.file_size,
                lv.uploaded_at,
                lv.gds_library_name
            FROM layer_versions lv
            JOIN layers l ON lv.layer_id = l.layer_id
            JOIN chips c ON l.chip_id = c.chip_id
            JOIN users u ON lv.uploaded_by = u.user_id
            WHERE lv.version_id = %s
        ''', (version_id,), fetch=True)

        if result and len(result) > 0:
            row = result[0]
            return {
                'version_id': row[0],
                'layer_id': row[1],
                'chip_number': row[2],
                'layer_name': row[3],
                'version_number': row[4],
                'username': row[5],
                'comment': row[6],
                'file_name': row[7],
                'file_size': row[8],
                'uploaded_at': row[9],
                'gds_library_name': row[10]
            }
        return None

    def delete_version(self, version_id):
        """Удаление версии"""
        return self.execute_query(
            "DELETE FROM layer_versions WHERE version_id = %s",
            (version_id,)
        )

    def get_version_count_by_layer(self, layer_id):
        """Получение количества версий для слоя"""
        result = self.execute_query(
            "SELECT COUNT(*) FROM layer_versions WHERE layer_id = %s",
            (layer_id,),
            fetch=True
        )
        return result[0][0] if result else 0

    # СТАТИСТИЧЕСКИЕ МЕТОДЫ

    def get_database_stats(self):
        """Получение статистики базы данных"""
        stats = {}

        # Количество пользователей
        result = self.execute_query("SELECT COUNT(*) FROM users", fetch=True)
        stats['user_count'] = result[0][0] if result else 0

        # Количество чипов
        result = self.execute_query("SELECT COUNT(*) FROM chips", fetch=True)
        stats['chip_count'] = result[0][0] if result else 0

        # Количество слоев
        result = self.execute_query("SELECT COUNT(*) FROM layers", fetch=True)
        stats['layer_count'] = result[0][0] if result else 0

        # Количество версий
        result = self.execute_query("SELECT COUNT(*) FROM layer_versions", fetch=True)
        stats['version_count'] = result[0][0] if result else 0

        # Общий размер файлов
        result = self.execute_query("SELECT COALESCE(SUM(file_size), 0) FROM layer_versions", fetch=True)
        stats['total_file_size'] = result[0][0] if result else 0

        # Последние активности
        result = self.execute_query(
            "SELECT MAX(uploaded_at) FROM layer_versions",
            fetch=True
        )
        stats['last_activity'] = result[0][0] if result else None

        return stats

    def get_user_activity_stats(self, user_id):
        """Получение статистики активности пользователя"""
        stats = {}

        # Количество загруженных версий
        result = self.execute_query(
            "SELECT COUNT(*) FROM layer_versions WHERE uploaded_by = %s",
            (user_id,),
            fetch=True
        )
        stats['uploaded_versions'] = result[0][0] if result else 0

        # Общий размер загруженных файлов
        result = self.execute_query(
            "SELECT COALESCE(SUM(file_size), 0) FROM layer_versions WHERE uploaded_by = %s",
            (user_id,),
            fetch=True
        )
        stats['total_upload_size'] = result[0][0] if result else 0

        # Последняя загрузка
        result = self.execute_query(
            "SELECT MAX(uploaded_at) FROM layer_versions WHERE uploaded_by = %s",
            (user_id,),
            fetch=True
        )
        stats['last_upload'] = result[0][0] if result else None

        return stats

    # МЕТОДЫ ПОИСКА

    def search_chips(self, search_term):
        """Поиск чипов по номеру или описанию"""
        search_pattern = '%' + search_term + '%'
        results = self.execute_query(
            "SELECT chip_id, chip_number, description, created_at FROM chips WHERE chip_number ILIKE %s OR description ILIKE %s ORDER BY chip_number",
            (search_pattern, search_pattern),
            fetch=True
        )

        chips = []
        for row in results:
            chips.append({
                'chip_id': row[0],
                'chip_number': row[1],
                'description': row[2],
                'created_at': row[3]
            })
        return chips

    def search_layers(self, search_term):
        """Поиск слоев по имени"""
        search_pattern = '%' + search_term + '%'
        results = self.execute_query('''
            SELECT l.layer_id, c.chip_number, l.layer_name, l.file_extension, l.created_at 
            FROM layers l 
            JOIN chips c ON l.chip_id = c.chip_id 
            WHERE l.layer_name ILIKE %s OR c.chip_number ILIKE %s
            ORDER BY c.chip_number, l.layer_name
        ''', (search_pattern, search_pattern), fetch=True)

        layers = []
        for row in results:
            layers.append({
                'layer_id': row[0],
                'chip_number': row[1],
                'layer_name': row[2],
                'file_extension': row[3],
                'created_at': row[4]
            })
        return layers


class DatabaseError(Exception):
    """Кастомное исключение для ошибок базы данных"""
    pass


# Утилитарные функции для работы с БД
class DatabaseUtils:
    @staticmethod
    def format_file_size(size_bytes):
        """Форматирование размера файла в читаемый вид"""
        if size_bytes == 0:
            return "0 B"

        size_names = ["B", "KB", "MB", "GB"]
        i = 0
        while size_bytes >= 1024 and i < len(size_names) - 1:
            size_bytes /= 1024.0
            i += 1

        return "{:.2f} {}".format(size_bytes, size_names[i])

    @staticmethod
    def validate_chip_number(chip_number):
        """Валидация номера чипа"""
        if not chip_number or len(chip_number.strip()) == 0:
            return False
        if len(chip_number) > 255:
            return False
        return True

    @staticmethod
    def validate_layer_name(layer_name):
        """Валидация имени слоя"""
        if not layer_name or len(layer_name.strip()) == 0:
            return False
        if len(layer_name) > 255:
            return False
        # Запрещенные символы
        forbidden_chars = ['/', '\\', ':', '*', '?', '"', '<', '>', '|']
        if any(char in layer_name for char in forbidden_chars):
            return False
        return True