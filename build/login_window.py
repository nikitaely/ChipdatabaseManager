# login_window.py
import tkinter as tk
import tkinter.ttk as ttk
import tkinter.messagebox as messagebox


class LoginWindow:
    def __init__(self, parent, auth_manager, on_login_success):
        self.parent = parent
        self.auth_manager = auth_manager
        self.on_login_success = on_login_success
        self.setup_ui()

    def setup_ui(self):
        """Создание полной формы входа/регистрации"""
        # Основной фрейм
        self.frame = ttk.Frame(self.parent, padding="20")
        self.frame.pack(expand=True)

        # Заголовок
        ttk.Label(
            self.frame,
            text="Chip Database Manager",
            font=('Arial', 16, 'bold')
        ).grid(row=0, column=0, columnspan=2, pady=(0, 20))

        # === СЕКЦИЯ ВХОДА ===
        login_frame = ttk.LabelFrame(self.frame, text="Login", padding="10")
        login_frame.grid(row=1, column=0, columnspan=2, sticky='ew', pady=(0, 20))

        # Поле имени пользователя для входа
        ttk.Label(login_frame, text="Username:").grid(row=0, column=0, sticky='e', pady=5)
        self.login_username = ttk.Entry(login_frame, width=25)
        self.login_username.grid(row=0, column=1, pady=5, padx=5)

        # Поле пароля для входа
        ttk.Label(login_frame, text="Password:").grid(row=1, column=0, sticky='e', pady=5)
        self.login_password = ttk.Entry(login_frame, width=25, show='*')
        self.login_password.grid(row=1, column=1, pady=5, padx=5)

        # Кнопка входа
        ttk.Button(
            login_frame,
            text="Login",
            command=self.login,
            width=15
        ).grid(row=2, column=0, columnspan=2, pady=10)

        # Разделитель
        ttk.Separator(self.frame, orient='horizontal').grid(
            row=2, column=0, columnspan=2, sticky='ew', pady=10
        )

        # === СЕКЦИЯ РЕГИСТРАЦИИ ===
        register_frame = ttk.LabelFrame(self.frame, text="Register New User", padding="10")
        register_frame.grid(row=3, column=0, columnspan=2, sticky='ew')

        # Поле полного имени
        ttk.Label(register_frame, text="Full Name:").grid(row=0, column=0, sticky='e', pady=5)
        self.reg_fullname = ttk.Entry(register_frame, width=25)
        self.reg_fullname.grid(row=0, column=1, pady=5, padx=5)

        # Поле имени пользователя для регистрации
        ttk.Label(register_frame, text="Username:").grid(row=1, column=0, sticky='e', pady=5)
        self.reg_username = ttk.Entry(register_frame, width=25)
        self.reg_username.grid(row=1, column=1, pady=5, padx=5)

        # Поле пароля для регистрации
        ttk.Label(register_frame, text="Password:").grid(row=2, column=0, sticky='e', pady=5)
        self.reg_password = ttk.Entry(register_frame, width=25, show='*')
        self.reg_password.grid(row=2, column=1, pady=5, padx=5)

        # Подтверждение пароля
        ttk.Label(register_frame, text="Confirm Password:").grid(row=3, column=0, sticky='e', pady=5)
        self.reg_confirm_password = ttk.Entry(register_frame, width=25, show='*')
        self.reg_confirm_password.grid(row=3, column=1, pady=5, padx=5)

        # Кнопка регистрации
        ttk.Button(
            register_frame,
            text="Register",
            command=self.register,
            width=15
        ).grid(row=4, column=0, columnspan=2, pady=10)

        # Привязка события Enter для полей ввода
        self.login_password.bind('<Return>', lambda event: self.login())
        self.reg_confirm_password.bind('<Return>', lambda event: self.register())

        # Фокус на поле имени пользователя для входа
        self.login_username.focus()

    def login(self):
        """Обработка входа пользователя"""
        username = self.login_username.get().strip()
        password = self.login_password.get()

        if not username or not password:
            messagebox.showerror("Error", "Please enter username and password")
            self.login_username.focus()
            return

        # Вызов метода аутентификации
        result = self.auth_manager.login_user(username, password)

        if result['success']:
            messagebox.showinfo("Success", result['message'])
            # Передаем данные пользователя в callback
            self.on_login_success({
                'user_id': result['user_id'],
                'username': result['username'],
                'full_name': result['full_name'],
                'role': result['role']  # Добавляем роль
            })
        else:
            messagebox.showerror("Error", result['message'])
            self.login_password.delete(0, tk.END)
            self.login_username.focus()

    def register(self):
        """Обработка регистрации нового пользователя"""
        fullname = self.reg_fullname.get().strip()
        username = self.reg_username.get().strip()
        password = self.reg_password.get()
        confirm_password = self.reg_confirm_password.get()

        # Валидация ввода
        if not all([fullname, username, password, confirm_password]):
            messagebox.showerror("Error", "All fields are required")
            self.reg_fullname.focus()
            return

        if password != confirm_password:
            messagebox.showerror("Error", "Passwords do not match")
            self.reg_password.delete(0, tk.END)
            self.reg_confirm_password.delete(0, tk.END)
            self.reg_password.focus()
            return

        # Проверка сложности пароля
        strength_result = self.auth_manager.validate_password_strength(password)
        if not strength_result['valid']:
            message_text = strength_result['message'] + "\n" + \
                           "Recommended: at least 8 characters with uppercase, " + \
                           "lowercase, digits and special characters"
            messagebox.showwarning("Weak Password", message_text)

            response = messagebox.askyesno(
                "Weak Password",
                strength_result['message'] + "\nDo you want to continue anyway?"
            )
            if not response:
                self.reg_password.delete(0, tk.END)
                self.reg_confirm_password.delete(0, tk.END)
                self.reg_password.focus()
                return

        # Вызов метода регистрации
        result = self.auth_manager.register_user(username, password, fullname)

        if result['success']:
            messagebox.showinfo("Success", result['message'])
            # Очистка полей после успешной регистрации
            self.clear_registration_fields()
            # Переключение фокуса на форму входа
            self.login_username.focus()
        else:
            messagebox.showerror("Error", result['message'])
            self.reg_username.focus()

    def clear_registration_fields(self):
        """Очистка полей регистрации"""
        self.reg_fullname.delete(0, tk.END)
        self.reg_username.delete(0, tk.END)
        self.reg_password.delete(0, tk.END)
        self.reg_confirm_password.delete(0, tk.END)

    def clear_login_fields(self):
        """Очистка полей входа"""
        self.login_username.delete(0, tk.END)
        self.login_password.delete(0, tk.END)

    def destroy(self):
        """Уничтожение окна"""
        self.frame.destroy()