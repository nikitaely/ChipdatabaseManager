FROM ubuntu:20.04

# Установка зависимостей
RUN apt-get update && apt-get install -y \
    python3 \
    python3-pip \
    python3-tk \
    libpq5 \
    binutils \
    && rm -rf /var/lib/apt/lists/*

# Установка Python пакетов
RUN pip3 install psycopg2-binary bcrypt pyinstaller

# Копирование исходного кода
WORKDIR /app
COPY . .

# Компиляция для Linux
RUN pyinstaller --onefile --name ChipDatabaseManager --add-data="config.json:." --hidden-import=psycopg2 --hidden-import=bcrypt main.py

# Копирование результата
RUN mkdir -p /output && cp dist/ChipDatabaseManager /output/