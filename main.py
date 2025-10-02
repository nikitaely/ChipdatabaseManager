import tkinter as tk
from tkinter import ttk, messagebox, filedialog
import psycopg2
from datetime import datetime
import hashlib
import bcrypt
import os


class ChipDatabaseApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Chip Design Database Manager")
        self.root.geometry("1200x800")

        # Параметры подключения к БД
        self.db_config = {
            'host': '192.168.7.109',
            'database': 'postgres',
            'user': 'postgres',
            'password': '1111',
            'port': 5432
        }

        self.current_user = None
        self.selected_file_path = None
        self.setup_database()
        self.create_login_frame()

    def setup_database(self):
        """Создание таблиц если их нет"""
        try:
            conn = psycopg2.connect(**self.db_config)
            cur = conn.cursor()

            # Создание таблицы users если не существует
            cur.execute('''
                CREATE TABLE IF NOT EXISTS users (
                    user_id SERIAL PRIMARY KEY,
                    username VARCHAR(255) UNIQUE NOT NULL,
                    password_hash VARCHAR(255) NOT NULL,
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
                    chip_id INTEGER REFERENCES chips(chip_id),
                    layer_name VARCHAR(255) NOT NULL,
                    file_extension VARCHAR(50),
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            ''')

            # Создание таблицы layer_versions если не существует
            cur.execute('''
                CREATE TABLE IF NOT EXISTS layer_versions (
                    version_id SERIAL PRIMARY KEY,
                    layer_id INTEGER REFERENCES layers(layer_id),
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
                    gds_units NUMERIC
                )
            ''')

            conn.commit()
            cur.close()
            conn.close()
        except Exception as e:
            messagebox.showerror("Database Error", "Failed to setup database: " + str(e))

    def hash_password(self, password):
        """Хэширование пароля"""
        return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

    def verify_password(self, password, hashed):
        """Проверка пароля"""
        return bcrypt.checkpw(password.encode('utf-8'), hashed.encode('utf-8'))

    def db_execute(self, query, params=None, fetch=False):
        """Универсальный метод выполнения запросов к БД"""
        try:
            conn = psycopg2.connect(**self.db_config)
            cur = conn.cursor()
            cur.execute(query, params)

            if fetch:
                result = cur.fetchall()
            else:
                conn.commit()
                result = None

            cur.close()
            conn.close()
            return result
        except Exception as e:
            messagebox.showerror("Database Error", str(e))
            return None

    def create_login_frame(self):
        """Форма входа/регистрации"""
        self.clear_frame()

        frame = ttk.Frame(self.root, padding="20")
        frame.pack(expand=True)

        ttk.Label(frame, text="Chip Database Manager", font=('Arial', 16)).grid(row=0, column=0, columnspan=2, pady=10)

        # Поля для входа
        ttk.Label(frame, text="Username:").grid(row=1, column=0, sticky='e', pady=5)
        self.login_username = ttk.Entry(frame, width=20)
        self.login_username.grid(row=1, column=1, pady=5)

        ttk.Label(frame, text="Password:").grid(row=2, column=0, sticky='e', pady=5)
        self.login_password = ttk.Entry(frame, width=20, show='*')
        self.login_password.grid(row=2, column=1, pady=5)

        ttk.Button(frame, text="Login", command=self.login).grid(row=3, column=0, columnspan=2, pady=10)

        # Разделитель
        ttk.Separator(frame, orient='horizontal').grid(row=4, column=0, columnspan=2, sticky='ew', pady=10)

        # Поля для регистрации
        ttk.Label(frame, text="Full Name:").grid(row=5, column=0, sticky='e', pady=5)
        self.reg_fullname = ttk.Entry(frame, width=20)
        self.reg_fullname.grid(row=5, column=1, pady=5)

        ttk.Label(frame, text="Username:").grid(row=6, column=0, sticky='e', pady=5)
        self.reg_username = ttk.Entry(frame, width=20)
        self.reg_username.grid(row=6, column=1, pady=5)

        ttk.Label(frame, text="Password:").grid(row=7, column=0, sticky='e', pady=5)
        self.reg_password = ttk.Entry(frame, width=20, show='*')
        self.reg_password.grid(row=7, column=1, pady=5)

        ttk.Button(frame, text="Register", command=self.register).grid(row=8, column=0, columnspan=2, pady=10)

    def login(self):
        """Вход пользователя"""
        username = self.login_username.get()
        password = self.login_password.get()

        result = self.db_execute(
            "SELECT user_id, password_hash, full_name FROM users WHERE username = %s",
            (username,),
            fetch=True
        )

        if result and self.verify_password(password, result[0][1]):
            self.current_user = {
                'user_id': result[0][0],
                'username': username,
                'full_name': result[0][2]
            }
            self.create_main_interface()
        else:
            messagebox.showerror("Error", "Invalid username or password")

    def register(self):
        """Регистрация нового пользователя"""
        fullname = self.reg_fullname.get()
        username = self.reg_username.get()
        password = self.reg_password.get()

        if not all([fullname, username, password]):
            messagebox.showerror("Error", "All fields are required")
            return

        password_hash = self.hash_password(password)

        result = self.db_execute(
            "INSERT INTO users (username, password_hash, full_name) VALUES (%s, %s, %s)",
            (username, password_hash, fullname)
        )

        if result is not None:
            messagebox.showinfo("Success", "User registered successfully!")
            self.reg_fullname.delete(0, tk.END)
            self.reg_username.delete(0, tk.END)
            self.reg_password.delete(0, tk.END)

    def create_main_interface(self):
        """Основной интерфейс приложения"""
        self.clear_frame()

        # Создаем notebook для вкладок
        notebook = ttk.Notebook(self.root)
        notebook.pack(expand=True, fill='both', padx=10, pady=10)

        # Вкладка управления чипами
        chips_frame = ttk.Frame(notebook)
        notebook.add(chips_frame, text="Chips Management")
        self.setup_chips_tab(chips_frame)

        # Вкладка управления слоями
        layers_frame = ttk.Frame(notebook)
        notebook.add(layers_frame, text="Layers Management")
        self.setup_layers_tab(layers_frame)

        # Вкладка управления версиями
        versions_frame = ttk.Frame(notebook)
        notebook.add(versions_frame, text="Versions Management")
        self.setup_versions_tab(versions_frame)

        # Панель пользователя
        user_frame = ttk.Frame(self.root)
        user_frame.pack(fill='x', padx=10, pady=5)

        ttk.Label(user_frame, text="Logged in as: " + self.current_user['full_name']).pack(side='left')
        ttk.Button(user_frame, text="Logout", command=self.create_login_frame).pack(side='right')

        # Обновляем все комбобоксы при создании интерфейса
        self.refresh_all_comboboxes()

    def setup_chips_tab(self, parent):
        """Вкладка управления чипами"""
        # Форма добавления чипа
        add_frame = ttk.LabelFrame(parent, text="Add New Chip", padding="10")
        add_frame.pack(fill='x', padx=10, pady=5)

        ttk.Label(add_frame, text="Chip Number:").grid(row=0, column=0, sticky='e', pady=5)
        self.chip_number = ttk.Entry(add_frame, width=30)
        self.chip_number.grid(row=0, column=1, pady=5, padx=5)

        ttk.Label(add_frame, text="Description:").grid(row=1, column=0, sticky='e', pady=5)
        self.chip_description = ttk.Entry(add_frame, width=30)
        self.chip_description.grid(row=1, column=1, pady=5, padx=5)

        ttk.Button(add_frame, text="Add Chip", command=self.add_chip).grid(row=2, column=0, columnspan=2, pady=10)

        # Таблица существующих чипов
        table_frame = ttk.LabelFrame(parent, text="Existing Chips", padding="10")
        table_frame.pack(fill='both', expand=True, padx=10, pady=5)

        columns = ('ID', 'Chip Number', 'Description', 'Created At')
        self.chips_tree = ttk.Treeview(table_frame, columns=columns, show='headings')

        for col in columns:
            self.chips_tree.heading(col, text=col)
            self.chips_tree.column(col, width=100)

        scrollbar = ttk.Scrollbar(table_frame, orient='vertical', command=self.chips_tree.yview)
        self.chips_tree.configure(yscrollcommand=scrollbar.set)

        self.chips_tree.pack(side='left', fill='both', expand=True)
        scrollbar.pack(side='right', fill='y')

        # Кнопка обновления таблицы
        ttk.Button(table_frame, text="Refresh", command=self.refresh_chips).pack(pady=5)

        self.refresh_chips()

    def setup_layers_tab(self, parent):
        """Вкладка управления слоями"""
        # Форма добавления слоя
        add_frame = ttk.LabelFrame(parent, text="Add New Layer", padding="10")
        add_frame.pack(fill='x', padx=10, pady=5)

        ttk.Label(add_frame, text="Select Chip:").grid(row=0, column=0, sticky='e', pady=5)
        self.chip_combobox = ttk.Combobox(add_frame, width=27, state='readonly')
        self.chip_combobox.grid(row=0, column=1, pady=5, padx=5)

        ttk.Label(add_frame, text="Layer Name:").grid(row=1, column=0, sticky='e', pady=5)
        self.layer_name = ttk.Entry(add_frame, width=30)
        self.layer_name.grid(row=1, column=1, pady=5, padx=5)

        ttk.Label(add_frame, text="File Extension:").grid(row=2, column=0, sticky='e', pady=5)
        self.file_extension = ttk.Entry(add_frame, width=30)
        self.file_extension.grid(row=2, column=1, pady=5, padx=5)

        ttk.Button(add_frame, text="Add Layer", command=self.add_layer).grid(row=3, column=0, columnspan=2, pady=10)

        # Таблица слоев
        table_frame = ttk.LabelFrame(parent, text="Existing Layers", padding="10")
        table_frame.pack(fill='both', expand=True, padx=10, pady=5)

        columns = ('Layer ID', 'Chip Number', 'Layer Name', 'File Extension', 'Created At')
        self.layers_tree = ttk.Treeview(table_frame, columns=columns, show='headings')

        for col in columns:
            self.layers_tree.heading(col, text=col)
            self.layers_tree.column(col, width=100)

        scrollbar = ttk.Scrollbar(table_frame, orient='vertical', command=self.layers_tree.yview)
        self.layers_tree.configure(yscrollcommand=scrollbar.set)

        self.layers_tree.pack(side='left', fill='both', expand=True)
        scrollbar.pack(side='right', fill='y')

        ttk.Button(table_frame, text="Refresh", command=self.refresh_layers).pack(pady=5)

    def setup_versions_tab(self, parent):
        """Вкладка управления версиями файлов"""
        # Форма добавления версии
        add_frame = ttk.LabelFrame(parent, text="Add New Version", padding="10")
        add_frame.pack(fill='x', padx=10, pady=5)

        ttk.Label(add_frame, text="Select Layer:").grid(row=0, column=0, sticky='e', pady=5)
        self.layer_combobox = ttk.Combobox(add_frame, width=27, state='readonly')
        self.layer_combobox.grid(row=0, column=1, pady=5, padx=5)

        ttk.Label(add_frame, text="Comment:").grid(row=1, column=0, sticky='e', pady=5)
        self.version_comment = ttk.Entry(add_frame, width=30)
        self.version_comment.grid(row=1, column=1, pady=5, padx=5)

        ttk.Label(add_frame, text="GDS Library Name:").grid(row=2, column=0, sticky='e', pady=5)
        self.gds_library = ttk.Entry(add_frame, width=30)
        self.gds_library.grid(row=2, column=1, pady=5, padx=5)

        ttk.Button(add_frame, text="Select File", command=self.select_file).grid(row=3, column=0, pady=5)
        self.file_path_label = ttk.Label(add_frame, text="No file selected")
        self.file_path_label.grid(row=3, column=1, pady=5, padx=5)

        ttk.Button(add_frame, text="Upload Version", command=self.upload_version).grid(row=4, column=0, columnspan=2,
                                                                                       pady=10)

        # Таблица версий
        table_frame = ttk.LabelFrame(parent, text="Version History", padding="10")
        table_frame.pack(fill='both', expand=True, padx=10, pady=5)

        columns = ('Version ID', 'Layer', 'Version', 'Uploaded By', 'Comment', 'File Name', 'Uploaded At')
        self.versions_tree = ttk.Treeview(table_frame, columns=columns, show='headings')

        for col in columns:
            self.versions_tree.heading(col, text=col)
            self.versions_tree.column(col, width=100)

        scrollbar = ttk.Scrollbar(table_frame, orient='vertical', command=self.versions_tree.yview)
        self.versions_tree.configure(yscrollcommand=scrollbar.set)

        self.versions_tree.pack(side='left', fill='both', expand=True)
        scrollbar.pack(side='right', fill='y')

        # Кнопки для работы с версиями
        btn_frame = ttk.Frame(table_frame)
        btn_frame.pack(pady=5)

        ttk.Button(btn_frame, text="Refresh", command=self.refresh_versions).pack(side='left', padx=5)
        ttk.Button(btn_frame, text="Download Selected", command=self.download_version).pack(side='left', padx=5)

    def refresh_all_comboboxes(self):
        """Обновление всех выпадающих списков"""
        self.refresh_chip_combobox()
        self.refresh_layer_combobox()
        self.refresh_chips()
        self.refresh_layers()
        self.refresh_versions()

    # МЕТОДЫ ДЛЯ РАБОТЫ С ДАННЫМИ

    def add_chip(self):
        """Добавление нового чипа"""
        chip_number = self.chip_number.get()
        description = self.chip_description.get()

        if not chip_number:
            messagebox.showerror("Error", "Chip number is required")
            return

        result = self.db_execute(
            "INSERT INTO chips (chip_number, description) VALUES (%s, %s)",
            (chip_number, description)
        )

        if result is not None:
            messagebox.showinfo("Success", "Chip added successfully!")
            self.chip_number.delete(0, tk.END)
            self.chip_description.delete(0, tk.END)
            self.refresh_all_comboboxes()

    def refresh_chips(self):
        """Обновление списка чипов в таблице"""
        # Очищаем таблицу
        for item in self.chips_tree.get_children():
            self.chips_tree.delete(item)

        # Загружаем данные из БД
        chips = self.db_execute(
            "SELECT chip_id, chip_number, description, created_at FROM chips ORDER BY created_at DESC",
            fetch=True
        )

        if chips:
            for chip in chips:
                self.chips_tree.insert('', 'end', values=chip)

    def refresh_chip_combobox(self):
        """Обновление выпадающего списка чипов"""
        chips = self.db_execute(
            "SELECT chip_id, chip_number FROM chips ORDER BY chip_number",
            fetch=True
        )

        if chips:
            # Сохраняем mapping chip_id -> chip_number для combobox
            self.chip_mapping = {}
            for chip in chips:
                display_text = chip[1] + " (ID: " + str(chip[0]) + ")"
                self.chip_mapping[display_text] = chip[0]

            self.chip_combobox['values'] = list(self.chip_mapping.keys())
            if self.chip_combobox['values']:
                self.chip_combobox.set(self.chip_combobox['values'][0])
        else:
            self.chip_combobox['values'] = []
            self.chip_combobox.set('')

    def add_layer(self):
        """Добавление нового слоя"""
        selected_chip = self.chip_combobox.get()
        layer_name = self.layer_name.get()
        file_extension = self.file_extension.get()

        if not all([selected_chip, layer_name]):
            messagebox.showerror("Error", "Chip selection and layer name are required")
            return

        chip_id = self.chip_mapping.get(selected_chip)

        result = self.db_execute(
            "INSERT INTO layers (chip_id, layer_name, file_extension) VALUES (%s, %s, %s)",
            (chip_id, layer_name, file_extension)
        )

        if result is not None:
            messagebox.showinfo("Success", "Layer added successfully!")
            self.layer_name.delete(0, tk.END)
            self.file_extension.delete(0, tk.END)

            # Явно обновляем комбобокс слоев во вкладке версий
            self.refresh_layer_combobox()
            self.refresh_layers()

    def refresh_layers(self):
        """Обновление списка слоев в таблице"""
        for item in self.layers_tree.get_children():
            self.layers_tree.delete(item)

        layers = self.db_execute('''
            SELECT l.layer_id, c.chip_number, l.layer_name, l.file_extension, l.created_at 
            FROM layers l 
            JOIN chips c ON l.chip_id = c.chip_id 
            ORDER BY l.created_at DESC
        ''', fetch=True)

        if layers:
            for layer in layers:
                self.layers_tree.insert('', 'end', values=layer)

    def refresh_layer_combobox(self):
        """Обновление выпадающего списка слоев для версий"""
        print("Refreshing layer combobox...")  # Отладочное сообщение

        layers = self.db_execute('''
            SELECT l.layer_id, c.chip_number, l.layer_name 
            FROM layers l 
            JOIN chips c ON l.chip_id = c.chip_id 
            ORDER BY c.chip_number, l.layer_name
        ''', fetch=True)

        if layers:
            self.layer_mapping = {}
            for layer in layers:
                display_text = layer[1] + " - " + layer[2] + " (ID: " + str(layer[0]) + ")"
                self.layer_mapping[display_text] = layer[0]

            self.layer_combobox['values'] = list(self.layer_mapping.keys())
            if self.layer_combobox['values']:
                self.layer_combobox.set(self.layer_combobox['values'][0])
            print("Layer combobox updated with " + str(len(layers)) + " layers")  # Отладочное сообщение
        else:
            self.layer_combobox['values'] = []
            self.layer_combobox.set('')
            print("No layers found for combobox")  # Отладочное сообщение

    def select_file(self):
        """Выбор файла для загрузки"""
        file_path = filedialog.askopenfilename(
            title="Select GDS file",
            filetypes=[("GDS files", "*.gds"), ("All files", "*.*")]
        )
        if file_path:
            self.selected_file_path = file_path
            self.file_path_label.config(text=file_path.split('/')[-1])

    def upload_version(self):
        """Загрузка новой версии файла"""
        selected_layer = self.layer_combobox.get()
        comment = self.version_comment.get()
        gds_library = self.gds_library.get()

        if not all([selected_layer, self.selected_file_path]):
            messagebox.showerror("Error", "Layer selection and file are required")
            return

        layer_id = self.layer_mapping.get(selected_layer)

        try:
            # Чтение файла
            with open(self.selected_file_path, 'rb') as f:
                file_data = f.read()

            file_name = os.path.basename(self.selected_file_path)
            file_size = len(file_data)
            file_hash = hashlib.md5(file_data).hexdigest()

            # Получаем номер следующей версии
            result = self.db_execute(
                "SELECT COALESCE(MAX(version_number), 0) + 1 FROM layer_versions WHERE layer_id = %s",
                (layer_id,),
                fetch=True
            )

            version_number = result[0][0] if result else 1

            # Вставляем версию
            self.db_execute('''
                INSERT INTO layer_versions 
                (layer_id, version_number, uploaded_by, comment, file_name, file_data, file_size, file_hash, mime_type, gds_library_name) 
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
            ''', (
                layer_id, version_number, self.current_user['user_id'], comment,
                file_name, file_data, file_size, file_hash, 'application/octet-stream', gds_library
            ))

            messagebox.showinfo("Success", "Version " + str(version_number) + " uploaded successfully!")
            self.version_comment.delete(0, tk.END)
            self.gds_library.delete(0, tk.END)
            self.file_path_label.config(text="No file selected")
            self.selected_file_path = None
            self.refresh_versions()

        except Exception as e:
            messagebox.showerror("Error", "Failed to upload file: " + str(e))

    def refresh_versions(self):
        """Обновление списка версий в таблице"""
        for item in self.versions_tree.get_children():
            self.versions_tree.delete(item)

        versions = self.db_execute('''
            SELECT lv.version_id, c.chip_number || ' - ' || l.layer_name, lv.version_number, 
                   u.username, lv.comment, lv.file_name, lv.uploaded_at
            FROM layer_versions lv
            JOIN layers l ON lv.layer_id = l.layer_id
            JOIN chips c ON l.chip_id = c.chip_id
            JOIN users u ON lv.uploaded_by = u.user_id
            ORDER BY lv.uploaded_at DESC
        ''', fetch=True)

        if versions:
            for version in versions:
                self.versions_tree.insert('', 'end', values=version)

    def download_version(self):
        """Скачивание выбранной версии файла"""
        selected = self.versions_tree.selection()
        if not selected:
            messagebox.showwarning("Warning", "Please select a version to download")
            return

        item = self.versions_tree.item(selected[0])
        version_id = item['values'][0]
        file_name = item['values'][5]

        # Получаем файл из БД
        result = self.db_execute(
            "SELECT file_data, file_name FROM layer_versions WHERE version_id = %s",
            (version_id,),
            fetch=True
        )

        if result:
            file_data = result[0][0]
            file_name = result[0][1]

            save_path = filedialog.asksaveasfilename(
                title="Save file as",
                initialfile=file_name,
                filetypes=[("GDS files", "*.gds"), ("All files", "*.*")]
            )

            if save_path:
                try:
                    with open(save_path, 'wb') as f:
                        f.write(file_data)
                    messagebox.showinfo("Success", "File saved as " + save_path)
                except Exception as e:
                    messagebox.showerror("Error", "Failed to save file: " + str(e))

    def clear_frame(self):
        """Очистка текущего фрейма"""
        for widget in self.root.winfo_children():
            widget.destroy()


def main():
    root = tk.Tk()
    app = ChipDatabaseApp(root)
    root.mainloop()


if __name__ == "__main__":
    main()