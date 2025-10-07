# main_window.py
import tkinter as tk
import tkinter.ttk as ttk
import tkinter.messagebox as messagebox
import tkinter.filedialog as filedialog
from datetime import datetime
import os


class MainWindow:
    def __init__(self, root, db_manager, auth_manager, file_manager, current_user):
        self.root = root
        self.root.title("Chip Design Database Manager")
        self.root.geometry("1200x800")

        self.db_manager = db_manager
        self.auth_manager = auth_manager
        self.file_manager = file_manager
        self.current_user = current_user

        # Переменные состояния
        self.selected_file_path = None
        self.chip_mapping = {}
        self.layer_mapping = {}

        # Виджеты
        self.notebook = None
        self.chip_combobox = None
        self.layer_combobox = None

        self.setup_ui()
        self.refresh_all_comboboxes()

    def setup_ui(self):
        """Создание основного интерфейса"""
        # Создаем notebook для вкладок
        self.notebook = ttk.Notebook(self.root)
        self.notebook.pack(expand=True, fill='both', padx=10, pady=10)

        # Вкладка управления чипами
        chips_frame = ttk.Frame(self.notebook)
        self.notebook.add(chips_frame, text="Chips Management")
        self.setup_chips_tab(chips_frame)

        # Вкладка управления слоями
        layers_frame = ttk.Frame(self.notebook)
        self.notebook.add(layers_frame, text="Layers Management")
        self.setup_layers_tab(layers_frame)

        # Вкладка управления версиями
        versions_frame = ttk.Frame(self.notebook)
        self.notebook.add(versions_frame, text="Versions Management")
        self.setup_versions_tab(versions_frame)

        # Панель пользователя
        self.setup_user_panel()

    def setup_user_panel(self):
        """Панель информации о пользователе"""
        user_frame = ttk.Frame(self.root)
        user_frame.pack(fill='x', padx=10, pady=5)

        ttk.Label(user_frame, text=f"Logged in as: {self.current_user['full_name']}").pack(side='left')
        ttk.Button(user_frame, text="Logout", command=self.logout).pack(side='right')

    def setup_chips_tab(self, parent):
        """Вкладка управления чипами"""
        # Форма добавления чипа
        add_frame = ttk.LabelFrame(parent, text="Add New Chip", padding="10")
        add_frame.pack(fill='x', padx=10, pady=5)

        ttk.Label(add_frame, text="Chip Number:").grid(row=0, column=0, sticky='e', pady=5)
        self.chip_number_entry = ttk.Entry(add_frame, width=30)
        self.chip_number_entry.grid(row=0, column=1, pady=5, padx=5)

        ttk.Label(add_frame, text="Description:").grid(row=1, column=0, sticky='e', pady=5)
        self.chip_description_entry = ttk.Entry(add_frame, width=30)
        self.chip_description_entry.grid(row=1, column=1, pady=5, padx=5)

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

        ttk.Button(table_frame, text="Refresh", command=self.refresh_chips).pack(pady=5)

    def setup_layers_tab(self, parent):
        """Вкладка управления слоями"""
        # Форма добавления слоя
        add_frame = ttk.LabelFrame(parent, text="Add New Layer", padding="10")
        add_frame.pack(fill='x', padx=10, pady=5)

        ttk.Label(add_frame, text="Select Chip:").grid(row=0, column=0, sticky='e', pady=5)
        self.chip_combobox = ttk.Combobox(add_frame, width=27, state='readonly')
        self.chip_combobox.grid(row=0, column=1, pady=5, padx=5)

        ttk.Label(add_frame, text="Layer Name:").grid(row=1, column=0, sticky='e', pady=5)
        self.layer_name_entry = ttk.Entry(add_frame, width=30)
        self.layer_name_entry.grid(row=1, column=1, pady=5, padx=5)

        ttk.Label(add_frame, text="File Extension:").grid(row=2, column=0, sticky='e', pady=5)
        self.file_extension_entry = ttk.Entry(add_frame, width=30)
        self.file_extension_entry.grid(row=2, column=1, pady=5, padx=5)

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
        self.version_comment_entry = ttk.Entry(add_frame, width=30)
        self.version_comment_entry.grid(row=1, column=1, pady=5, padx=5)

        ttk.Label(add_frame, text="GDS Library Name:").grid(row=2, column=0, sticky='e', pady=5)
        self.gds_library_entry = ttk.Entry(add_frame, width=30)
        self.gds_library_entry.grid(row=2, column=1, pady=5, padx=5)

        ttk.Button(add_frame, text="Select File", command=self.select_file).grid(row=3, column=0, pady=5)
        self.file_path_label = ttk.Label(add_frame, text="No file selected")
        self.file_path_label.grid(row=3, column=1, pady=5, padx=5)

        ttk.Button(add_frame, text="Upload Version", command=self.upload_version).grid(
            row=4, column=0, columnspan=2, pady=10
        )

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

    # МЕТОДЫ ДЛЯ РАБОТЫ С ДАННЫМИ

    def refresh_all_comboboxes(self):
        """Обновление всех выпадающих списков"""
        self.refresh_chip_combobox()
        self.refresh_layer_combobox()
        self.refresh_chips()
        self.refresh_layers()
        self.refresh_versions()

    def refresh_chip_combobox(self):
        """Обновление выпадающего списка чипов"""
        chips = self.db_manager.get_all_chips()

        if chips:
            self.chip_mapping = {}
            chip_values = []
            for chip in chips:
                display_text = f"{chip['chip_number']} (ID: {chip['chip_id']})"
                chip_values.append(display_text)
                self.chip_mapping[display_text] = chip['chip_id']

            if self.chip_combobox:
                current_value = self.chip_combobox.get()
                self.chip_combobox['values'] = chip_values
                if chip_values:
                    if current_value in chip_values:
                        self.chip_combobox.set(current_value)
                    else:
                        self.chip_combobox.set(chip_values[0])
                else:
                    self.chip_combobox.set('')

    def refresh_layer_combobox(self):
        """Обновление выпадающего списка слоев"""
        layers = self.db_manager.get_all_layers_with_chips()

        if layers:
            self.layer_mapping = {}
            layer_values = []
            for layer in layers:
                display_text = f"{layer['chip_number']} - {layer['layer_name']} (ID: {layer['layer_id']})"
                layer_values.append(display_text)
                self.layer_mapping[display_text] = layer['layer_id']

            if self.layer_combobox:
                current_value = self.layer_combobox.get()
                self.layer_combobox['values'] = layer_values
                if layer_values:
                    if current_value in layer_values:
                        self.layer_combobox.set(current_value)
                    else:
                        self.layer_combobox.set(layer_values[0])
                else:
                    self.layer_combobox.set('')

    def add_chip(self):
        """Добавление нового чипа"""
        chip_number = self.chip_number_entry.get()
        description = self.chip_description_entry.get()

        if not chip_number:
            messagebox.showerror("Error", "Chip number is required")
            return

        try:
            self.db_manager.add_chip(chip_number, description)
            messagebox.showinfo("Success", "Chip added successfully!")
            self.chip_number_entry.delete(0, tk.END)
            self.chip_description_entry.delete(0, tk.END)
            self.refresh_all_comboboxes()
        except Exception as e:
            messagebox.showerror("Error", f"Failed to add chip: {str(e)}")

    def refresh_chips(self):
        """Обновление списка чипов в таблице"""
        for item in self.chips_tree.get_children():
            self.chips_tree.delete(item)

        chips = self.db_manager.get_all_chips()

        if chips:
            for chip in chips:
                self.chips_tree.insert('', 'end', values=(
                    chip['chip_id'],
                    chip['chip_number'],
                    chip['description'],
                    chip['created_at']
                ))

    def add_layer(self):
        """Добавление нового слоя"""
        selected_chip = self.chip_combobox.get()
        layer_name = self.layer_name_entry.get()
        file_extension = self.file_extension_entry.get()

        if not selected_chip or not layer_name:
            messagebox.showerror("Error", "Chip selection and layer name are required")
            return

        chip_id = self.chip_mapping.get(selected_chip)

        try:
            self.db_manager.add_layer(chip_id, layer_name, file_extension)
            messagebox.showinfo("Success", "Layer added successfully!")
            self.layer_name_entry.delete(0, tk.END)
            self.file_extension_entry.delete(0, tk.END)
            self.refresh_all_comboboxes()
        except Exception as e:
            messagebox.showerror("Error", f"Failed to add layer: {str(e)}")

    def refresh_layers(self):
        """Обновление списка слоев в таблице"""
        for item in self.layers_tree.get_children():
            self.layers_tree.delete(item)

        layers = self.db_manager.get_all_layers_with_chips()

        if layers:
            for layer in layers:
                self.layers_tree.insert('', 'end', values=(
                    layer['layer_id'],
                    layer['chip_number'],
                    layer['layer_name'],
                    layer['file_extension'],
                    layer['created_at']
                ))

    def select_file(self):
        """Выбор файла для загрузки"""
        file_path = filedialog.askopenfilename(
            title="Select GDS file",
            filetypes=[("GDS files", "*.gds"), ("All files", "*.*")]
        )
        if file_path:
            self.selected_file_path = file_path
            file_name = os.path.basename(file_path)
            self.file_path_label.config(text=file_name)

    def upload_version(self):
        """Загрузка новой версии файла"""
        selected_layer = self.layer_combobox.get()
        comment = self.version_comment_entry.get()
        gds_library = self.gds_library_entry.get()

        if not selected_layer or not self.selected_file_path:
            messagebox.showerror("Error", "Layer selection and file are required")
            return

        layer_id = self.layer_mapping.get(selected_layer)

        try:
            # Чтение файла
            file_data = self.file_manager.read_file(self.selected_file_path)
            file_name = os.path.basename(self.selected_file_path)

            # Загрузка в БД
            self.db_manager.add_version(
                layer_id=layer_id,
                user_id=self.current_user['user_id'],
                file_data=file_data,
                comment=comment,
                file_name=file_name,
                gds_library_name=gds_library
            )

            messagebox.showinfo("Success", "Version uploaded successfully!")
            self.version_comment_entry.delete(0, tk.END)
            self.gds_library_entry.delete(0, tk.END)
            self.file_path_label.config(text="No file selected")
            self.selected_file_path = None
            self.refresh_versions()

        except Exception as e:
            messagebox.showerror("Error", f"Failed to upload file: {str(e)}")

    def refresh_versions(self):
        """Обновление списка версий в таблице"""
        for item in self.versions_tree.get_children():
            self.versions_tree.delete(item)

        versions = self.db_manager.get_all_versions()

        if versions:
            for version in versions:
                self.versions_tree.insert('', 'end', values=(
                    version['version_id'],
                    version['layer_display'],
                    version['version_number'],
                    version['username'],
                    version['comment'],
                    version['file_name'],
                    version['uploaded_at']
                ))

    def download_version(self):
        """Скачивание выбранной версии файла"""
        selected = self.versions_tree.selection()
        if not selected:
            messagebox.showwarning("Warning", "Please select a version to download")
            return

        item = self.versions_tree.item(selected[0])
        version_id = item['values'][0]

        try:
            version_data = self.db_manager.get_version_data(version_id)
            if version_data:
                file_data = version_data['file_data']
                file_name = version_data['file_name']

                save_path = filedialog.asksaveasfilename(
                    title="Save file as",
                    initialfile=file_name,
                    filetypes=[("GDS files", "*.gds"), ("All files", "*.*")]
                )

                if save_path:
                    self.file_manager.save_file(file_data, save_path)
                    messagebox.showinfo("Success", f"File saved as {save_path}")

        except Exception as e:
            messagebox.showerror("Error", f"Failed to download file: {str(e)}")

    def logout(self):
        """Выход из системы"""
        for widget in self.root.winfo_children():
            widget.destroy()
        # Здесь должен быть callback для возврата к окну логина
        # self.on_logout_callback()