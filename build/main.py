# main.py
import tkinter as tk
from login_window import LoginWindow
from main_window import MainWindow
from database import DatabaseManager
from auth import AuthManager
from file_manager import FileManager


class ChipDatabaseApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Chip Design Database Manager")

        # Конфигурация базы данных
        self.db_config = {
            'host': '192.168.7.109',
            'database': 'postgres',
            'user': 'postgres',
            'password': '1111',
            'port': 5432
        }

        # Инициализация менеджеров
        self.setup_managers()

        # Текущий пользователь
        self.current_user = None

        # Показать окно входа
        self.show_login()

    def setup_managers(self):
        """Инициализация всех менеджеров"""
        try:
            self.db_manager = DatabaseManager(self.db_config)
            self.auth_manager = AuthManager(self.db_config)
            self.file_manager = FileManager()

            # Создание таблиц если их нет
            self.db_manager.setup_tables()

        except Exception as e:
            tk.messagebox.showerror(
                "Initialization Error",
                "Failed to initialize application: "+ str(e)
            )
            self.root.quit()

    def show_login(self):
        """Показать окно входа"""
        # Очистка существующих виджетов
        for widget in self.root.winfo_children():
            widget.destroy()

        self.login_window = LoginWindow(
            self.root,
            self.auth_manager,
            self.on_login_success
        )

    def on_login_success(self, user_data):
        """Callback при успешном входе"""
        self.current_user = user_data
        self.show_main_interface()

    def show_main_interface(self):
        """Показать основной интерфейс"""
        # Очистка существующих виджетов
        for widget in self.root.winfo_children():
            widget.destroy()

        self.main_window = MainWindow(
            self.root,
            self.db_manager,
            self.auth_manager,
            self.file_manager,
            self.current_user
        )

    def logout(self):
        """Выход из системы"""
        self.current_user = None
        self.show_login()


def main():
    root = tk.Tk()
    root.geometry("600x500")  # Увеличенный размер для формы входа
    root.minsize(500, 400)  # Минимальный размер

    app = ChipDatabaseApp(root)
    root.mainloop()


if __name__ == "__main__":
    main()