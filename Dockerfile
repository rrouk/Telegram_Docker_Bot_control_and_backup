# Используем официальный легковесный образ Python 3.11
FROM python:3.11-slim

# Установка рабочей директории в контейнере
WORKDIR /app

# Копирование файла требований и установка зависимостей.
# --no-cache-dir уменьшает размер финального образа.
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Копирование файлов приложения
# Файл с логикой шифрования
COPY cipher_logic.py .
# Основной скрипт бота
COPY bot.py .
# Файл .env с токеном и паролями (для чтения при запуске)
COPY .env . 

# Создаем папку, которую будем архивировать. 
# В Docker Compose эта папка будет точкой монтирования тома с хоста.
RUN mkdir -p /app/data_to_archive

# Команда для запуска бота
CMD ["python", "bot.py"]