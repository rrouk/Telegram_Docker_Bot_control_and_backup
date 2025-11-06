# -*- coding: utf-8 -*-
import os
import asyncio
import docker
import html
import shutil 
from datetime import datetime, timezone 
from telegram import Update, InlineKeyboardButton, InlineKeyboardMarkup
from telegram.ext import Application, CommandHandler, CallbackQueryHandler, ContextTypes
from dotenv import load_dotenv
from typing import Optional # Добавлен для Optional
import logging
from apscheduler.schedulers.asyncio import AsyncIOScheduler
from apscheduler.triggers.cron import CronTrigger
import pytz



# Настройка логирования в начале файла (должна быть)
logging.basicConfig(level=logging.INFO, 
                    format='%(asctime)s - %(processName)s - %(name)s - %(levelname)s - %(message)s')


# ИМПОРТИРУЙТЕ ВАШУ ЛОГИКУ ШИФРОВАНИЯ
# Убедитесь, что файл cipher_logic.py находится в той же папке
try:
    from cipher_logic import AESGCMCipher
except ImportError:
    logging.info("❌ Ошибка: Не найден модуль cipher_logic.py. Функции шифрования не будут работать.")
    AESGCMCipher = None


load_dotenv()

class DockerBot:
    def __init__(self):
        self.bot_token = os.getenv('BOT_TOKEN')
        self.allowed_users = [int(user_id) for user_id in os.getenv('ALLOWED_USERS', '').split(',') if user_id]
        
        # --- Настройки Шифрования из .env ---
        self.enc_password = os.getenv("ENCRYPTION_PASSWORD")
        self.iter_password = os.getenv("ITERATIONS_PASSWORD", "")
        # Используем путь внутри контейнера, указанный в .env
        self.folder_to_archive = os.getenv("FOLDER_TO_ARCHIVE") or "/app/data_to_archive"
        
        # ------------------------------------

        if not self.enc_password:
             logging.info("⚠️ ВНИМАНИЕ: Пароль шифрования (ENCRYPTION_PASSWORD) не установлен в .env.")
        
        # Проверка и создание папки
        if not os.path.isdir(self.folder_to_archive):
            os.makedirs(self.folder_to_archive, exist_ok=True)
            logging.info(f"Папка {self.folder_to_archive} не найдена. Создана пустая папка.")

        try:
            # Проверка, что Docker Socket смонтирован
            if not os.path.exists('/var/run/docker.sock'):
                raise Exception("Docker socket не найден: /var/run/docker.sock")

            self.docker_client = docker.DockerClient(base_url='unix:///var/run/docker.sock')
            self.docker_client.ping()
            logging.info("Docker подключение успешно установлено")
        except Exception as e:
            logging.info(f"Ошибка подключения к Docker: {e}")
            logging.info("Убедитесь, что Docker socket смонтирован в контейнер")
            self.docker_client = None 

    # --- Вспомогательные функции ---

    def _escape_html(self, text):
        """Экранирует специальные символы HTML для безопасного отображения"""
        return html.escape(str(text))

    def _format_uptime(self, started_at_str):
        if not started_at_str: return "N/A"
        import datetime
        s = started_at_str
        try:
            s = s.replace('Z', '+00:00')
            dot_index = s.find('.'); tz_index = s.find('+') 
            if dot_index != -1 and tz_index != -1:
                frac_len = tz_index - (dot_index + 1)
                if frac_len > 6: s = s[:dot_index + 1 + 6] + s[tz_index:]
                elif frac_len == 0: s = s[:dot_index] + s[tz_index:]
            try: started_at = datetime.datetime.strptime(s, "%Y-%m-%dT%H:%M:%S.%f%z")
            except ValueError: started_at = datetime.datetime.strptime(s, "%Y-%m-%dT%H:%M:%S%z")
            now = datetime.datetime.now(timezone.utc)
            diff = now - started_at
            seconds = int(diff.total_seconds())
            if seconds < 0: return "Unknown"
            if seconds < 60: return f"{seconds} сек"
            elif seconds < 3600: return f"{seconds // 60} мин"
            elif seconds < 86400: return f"{seconds // 3600} ч {(seconds % 3600) // 60} мин"
            else: return f"{seconds // 86400} д {(seconds % 86400) // 3600} ч"
        except Exception as e: return f"Raw: {started_at_str}"

    async def create_archive_and_encrypt(self, folder_path: str, output_file: str) -> tuple[str, int]:
        """Архивирует папку, шифрует архив и возвращает путь к зашифрованному файлу и итерации."""
        if not AESGCMCipher:
            raise Exception("Модуль шифрования (cipher_logic.py) не загружен.")
        if not self.enc_password:
             raise Exception("Пароль шифрования (ENCRYPTION_PASSWORD) не установлен.")

        current_dir = os.getcwd() 
        temp_zip_path_base = os.path.join(current_dir, os.path.basename(folder_path))
        
        try:
            shutil.make_archive(
                base_name=temp_zip_path_base,
                format='zip', 
                root_dir=os.path.dirname(folder_path), 
                base_dir=os.path.basename(folder_path)
            )
            temp_zip_path = temp_zip_path_base + ".zip"
        except Exception as e:
            logging.info(f"Ошибка архивирования: {e}")
            raise

        try:
            with open(temp_zip_path, 'rb') as f:
                archive_data = f.read()
        finally:
            if os.path.exists(temp_zip_path):
                os.remove(temp_zip_path)

        cipher = AESGCMCipher(self.enc_password, self.iter_password)
        encrypted_data, iterations = cipher.encrypt(archive_data, iterations=None) 

        with open(output_file, 'wb') as f:
            f.write(encrypted_data)

        return output_file, iterations

    # --- Docker-функции (не изменены) ---

    async def get_containers(self):
        if not self.docker_client: return []
        # ... (код get_containers)
        try:
            containers = self.docker_client.containers.list(all=True)
            result = []
            for container in containers:
                if container.image.tags: image_tag = container.image.tags[0]
                else: image_tag = container.image.short_id
                started_at = None
                try: started_at = container.attrs['State'].get('StartedAt')
                except (KeyError, AttributeError): started_at = None
                result.append({'name': container.name, 'status': container.status, 'image': image_tag, 'started_at': started_at})
            return result
        except Exception as e:
            logging.info(f"Ошибка при получении контейнеров: {e}")
            return []

    async def start_container(self, container_name):
        if not self.docker_client: return False
        try:
            container = self.docker_client.containers.get(container_name)
            container.start()
            return True
        except Exception as e:
            logging.info(f"Ошибка при запуске контейнера: {e}")
            return False

    async def stop_container(self, container_name):
        if not self.docker_client: return False
        try:
            container = self.docker_client.containers.get(container_name)
            container.stop()
            return True
        except Exception as e:
            logging.info(f"Ошибка при остановке контейнера: {e}")
            return False

    async def restart_container(self, container_name):
        if not self.docker_client: return False
        try:
            container = self.docker_client.containers.get(container_name)
            container.restart()
            return True
        except Exception as e:
            logging.info(f"Ошибка при перезапуске контейнера: {e}")
            return False

    async def get_container_logs(self, container_name, lines=20):
        if not self.docker_client: return "Docker клиент недоступен."
        try:
            container = self.docker_client.containers.get(container_name)
            logs = container.logs(tail=lines).decode('utf-8')
            return logs
        except Exception as e:
            logging.info(f"Ошибка при получении логов: {e}")
            return f"Ошибка при получении логов: {self._escape_html(e)}"

    # --- Обработчики Telegram ---

    async def start(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """Команда /start"""
        user_id = update.effective_user.id
        if hasattr(self, 'allowed_users') and self.allowed_users and user_id not in self.allowed_users:
            await update.message.reply_text("❌ У вас нет доступа к этому боту.")
            return

        keyboard = [
            [InlineKeyboardButton("📋 Список контейнеров", callback_data="list")],
            [InlineKeyboardButton("🔒 Зашифровать архив", callback_data="encrypt_archive")],
        ]
        reply_markup = InlineKeyboardMarkup(keyboard)

        await update.message.reply_text(
            "🐳 <b>Docker Bot</b>\n\nВыберите действие:",
            reply_markup=reply_markup, parse_mode='HTML'
        )

    async def button_handler(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """Обработка нажатий на кнопки"""
        query = update.callback_query
        await query.answer()

        if query.data == "list":
            await self.show_containers(query)
        elif query.data == "back":
            await self.start_menu(query)
        elif query.data == "encrypt_archive": 
             await self.handle_encrypt_archive(query, context)
        elif query.data.startswith("container_"):
            await self.show_container_info(query)
        elif query.data.startswith("action_"):
            await self.handle_action(query)

    async def start_menu(self, query):
        """Показать главное меню"""
        keyboard = [
            [InlineKeyboardButton("📋 Список контейнеров", callback_data="list")],
            [InlineKeyboardButton("🔒 Зашифровать архив", callback_data="encrypt_archive")],
        ]
        reply_markup = InlineKeyboardMarkup(keyboard)

        await query.edit_message_text(
            "🐳 <b>Docker Bot</b>\n\nВыберите действие:",
            reply_markup=reply_markup, parse_mode='HTML'
        )
    
    async def handle_encrypt_archive(self, query, context: ContextTypes.DEFAULT_TYPE):
        """Архивирует заданную папку, шифрует ее и отправляет в чат."""
        
        if not self.enc_password:
            await query.edit_message_text("❌ Ошибка: Пароль шифрования (ENCRYPTION_PASSWORD) не задан в .env.", parse_mode='HTML')
            return
        
        folder_display_name = self._escape_html(os.path.basename(self.folder_to_archive))
        
        message = await query.edit_message_text(
            f"⏳ Начинаю архивацию и шифрование папки <code>{folder_display_name}</code>...", 
            parse_mode='HTML'
        )

        output_filename = ""
        encrypted_filepath = ""
        try:
            server_names_env = os.getenv("server_names_env")
            timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")
            output_filename = f"{server_names_env}-{timestamp}.zip.enc"
            
            encrypted_filepath, iterations = await self.create_archive_and_encrypt(
                self.folder_to_archive, 
                os.path.join(os.getcwd(), output_filename)
            )

            await context.bot.send_document(
                chat_id=query.message.chat_id,
                document=encrypted_filepath,
                caption=(
                    f"✅ <b>Архив зашифрован!</b>\n\n"
                ),
                parse_mode='HTML'
            )
            
            await context.bot.edit_message_text(
                chat_id=query.message.chat_id,
                message_id=message.message_id,
                text=f"✅ Архив успешно зашифрован и отправлен.",
                parse_mode='HTML'
            )

        except Exception as e:
            error_message = self._escape_html(f"При архивации/шифровании: {e}")
            await context.bot.edit_message_text(
                chat_id=query.message.chat_id,
                message_id=message.message_id,
                text=f"❌ **Критическая ошибка:**\n\n<code>{error_message}</code>",
                parse_mode='HTML'
            )
        finally:
            if encrypted_filepath and os.path.exists(encrypted_filepath):
                os.remove(encrypted_filepath)

        await self.start_menu(query)
    
    async def show_containers(self, query):
        """Display the list of containers including status, image, and uptime."""
        if not self.docker_client:
            await query.edit_message_text("❌ Docker клиент недоступен для управления контейнерами.", parse_mode='HTML')
            return await self.start_menu(query)

        containers = await self.get_containers()

        if not containers:
            await query.edit_message_text("📋 Контейнеры не найдены", parse_mode='HTML')
            return

        message = "📋 <b>Список контейнеров:</b>\n\n"
        keyboard = []

        for container in containers:
            status = container['status']
            started_at = container.get('started_at')

            status_emoji = "🟢" if status == 'running' else "🔴"

            uptime_str = "N/A"
            if status == 'running' and started_at: uptime_str = self._format_uptime(started_at)
            
            escaped_name = self._escape_html(container['name'])
            escaped_image = self._escape_html(container['image'])
            
            message += f"{status_emoji} <code>{escaped_name}</code>\n"
            message += f"    Статус: {status}\n"
            message += f"    Образ: {escaped_image}\n"
            message += f"    Время работы: {uptime_str}\n\n"

            keyboard.append([
                InlineKeyboardButton(
                    f"{'⏹️' if status == 'running' else '▶️'} {container['name']}",
                    callback_data=f"container_{container['name']}"
                )
            ])

        # ⬇️ ИСПРАВЛЕНИЕ 2: Удалена кнопка "Зашифровать архив" из списка контейнеров
        keyboard.append([InlineKeyboardButton("🔙 Назад", callback_data="back")])
        reply_markup = InlineKeyboardMarkup(keyboard)

        await query.edit_message_text(message, reply_markup=reply_markup, parse_mode='HTML')


    async def show_container_info(self, query, container_name: Optional[str] = None):
        """Показать информацию о контейнере."""
        if not self.docker_client: return await self.start_menu(query)
        
        # ⬇️ ИСПРАВЛЕНИЕ 1 (часть 2): Парсим имя, если оно не было передано явно
        if not container_name:
            try: container_name = query.data.split("_", 1)[1]
            except IndexError:
                await query.edit_message_text("❌ Ошибка: Неверный формат данных для контейнера.", parse_mode='HTML')
                return

        try:
            container = self.docker_client.containers.get(container_name)
            status = container.status

            if container.image.tags: image_tag = container.image.tags[0]
            else: image_tag = container.image.short_id

            escaped_name = self._escape_html(container_name)
            escaped_image = self._escape_html(image_tag)
            
            message = f"🐳 <b>{escaped_name}</b>\n\n"
            message += f"Статус: {status}\n"
            message += f"Образ: <code>{escaped_image}</code>\n\n"

            keyboard = []

            if status == 'running':
                keyboard.append([InlineKeyboardButton("⏹️ Остановить", callback_data=f"action_stop_{container_name}")])
                keyboard.append([InlineKeyboardButton("🔄 Перезапустить", callback_data=f"action_restart_{container_name}")])
            else:
                keyboard.append([InlineKeyboardButton("▶️ Запустить", callback_data=f"action_start_{container_name}")])

            keyboard.append([InlineKeyboardButton("📝 Логи", callback_data=f"action_logs_{container_name}")])
            keyboard.append([InlineKeyboardButton("🔙 Назад", callback_data="list")])

            reply_markup = InlineKeyboardMarkup(keyboard)
            await query.edit_message_text(message, reply_markup=reply_markup, parse_mode='HTML')
        except docker.errors.NotFound:
             await query.edit_message_text(f"❌ Ошибка: Контейнер с именем <code>{self._escape_html(container_name)}</code> не найден.", parse_mode='HTML')
        except Exception as e:
            await query.edit_message_text(f"❌ Ошибка при получении информации о контейнере: {self._escape_html(e)}", parse_mode='HTML')


    async def handle_action(self, query):
        """Обработка действий с контейнерами"""
        if not self.docker_client: return await self.start_menu(query)
        
        data = query.data.split("_")
        action = data[1]
        container_name = "_".join(data[2:])
        escaped_name = self._escape_html(container_name)

        if action == "start":
            success = await self.start_container(container_name)
            if success: await query.edit_message_text(f"✅ Контейнер <code>{escaped_name}</code> запущен", parse_mode='HTML')
            else: await query.edit_message_text(f"❌ Ошибка при запуске контейнера <code>{escaped_name}</code>", parse_mode='HTML')
        elif action == "stop":
            success = await self.stop_container(container_name)
            if success: await query.edit_message_text(f"⏹️ Контейнер <code>{escaped_name}</code> остановлен", parse_mode='HTML')
            else: await query.edit_message_text(f"❌ Ошибка при остановке контейнера <code>{escaped_name}</code>", parse_mode='HTML')
        elif action == "restart":
            success = await self.restart_container(container_name)
            if success: await query.edit_message_text(f"🔄 Контейнер <code>{escaped_name}</code> перезапущен", parse_mode='HTML')
            else: await query.edit_message_text(f"❌ Ошибка при перезапуске контейнера <code>{escaped_name}</code>", parse_mode='HTML')
        elif action == "logs":
            logs = await self.get_container_logs(container_name, 20)
            
            if len(logs) > 3000: logs = logs[-3000:] + "\n\n... (показаны последние 20 строк)"

            escaped_logs = self._escape_html(logs)
            message = f"📝 <b>Логи <code>{escaped_name}</code>:</b>\n\n<pre>{escaped_logs}</pre>"
            
            # Кнопка "Назад" ведет обратно в меню контейнера
            keyboard = [[InlineKeyboardButton("🔙 Назад", callback_data=f"container_{container_name}")]]
            reply_markup = InlineKeyboardMarkup(keyboard)

            await query.edit_message_text(message, reply_markup=reply_markup, parse_mode='HTML')
        
        # ⬇️ ИСПРАВЛЕНИЕ 1 (часть 1): Возвращаемся в меню контейнера после управления
        if action in ["start", "stop", "restart"]:
            await asyncio.sleep(1) # Ждем, пока Docker обновит статус
            # Вызываем show_container_info с именем контейнера
            await self.show_container_info(query, container_name)
        
        # ВНИМАНИЕ: Старый код, вызывающий self.start_menu(query), удален.




    async def scheduled_encrypt_and_send(self, bot):
        """Автоматическая отправка архива по расписанию"""
        if not self.enc_password:
            logging.error("❌ Невозможно отправить архив: пароль шифрования не задан.")
            return

        folder_display_name = self._escape_html(os.path.basename(self.folder_to_archive))
        chat_id = int(os.getenv("ARCHIVE_CHAT_ID", "0"))
        thread_id_str = os.getenv("ARCHIVE_MESSAGE_THREAD_ID", "").strip()
        message_thread_id = int(thread_id_str) if thread_id_str.isdigit() else None

        if chat_id == 0:
            logging.error("❌ ARCHIVE_CHAT_ID не задан в .env — автоматическая отправка невозможна.")
            return

        try:
            server_names_env = os.getenv("server_names_env", "backup")
            timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")
            output_filename = f"{server_names_env}-{timestamp}.zip.enc"
            encrypted_filepath = os.path.join(os.getcwd(), output_filename)

            logging.info(f"⏳ Запуск автоматической архивации папки {self.folder_to_archive}...")
            encrypted_filepath, iterations = await self.create_archive_and_encrypt(
                self.folder_to_archive,
                encrypted_filepath
            )

            caption = f"🌙 <b>Автоматический ночной бэкап</b>\n📁 Папка: <code>{folder_display_name}</code>"
            await bot.send_document(
                chat_id=chat_id,
                message_thread_id=message_thread_id,
                document=encrypted_filepath,
                caption=caption,
                parse_mode='HTML'
            )
            logging.info("✅ Автоматический архив успешно отправлен.")

        except Exception as e:
            error_msg = self._escape_html(str(e))
            logging.error(f"❌ Ошибка при автоматической архивации: {error_msg}")
            try:
                await bot.send_message(
                    chat_id=chat_id,
                    message_thread_id=message_thread_id,
                    text=f"❌ Ошибка при создании ночного бэкапа:\n<code>{error_msg}</code>",
                    parse_mode='HTML'
                )
            except Exception as send_err:
                logging.error(f"Не удалось отправить уведомление об ошибке: {send_err}")
        finally:
            if 'encrypted_filepath' in locals() and os.path.exists(encrypted_filepath):
                os.remove(encrypted_filepath)



    async def post_init(self, application: Application):
        """Вызывается после инициализации бота, когда event loop уже запущен"""
        from apscheduler.schedulers.asyncio import AsyncIOScheduler
        from apscheduler.triggers.cron import CronTrigger
        import pytz

        # Получаем настройки времени
        HOUR_TIME_PLAN = int(os.getenv("HOUR_TIME_PLAN", "0"))
        MINUTE_TIME_PLAN = int(os.getenv("MINUTE_TIME_PLAN", "0"))

        # Создаём планировщик
        scheduler = AsyncIOScheduler(timezone=pytz.timezone("Europe/Moscow"))
        scheduler.add_job(
            self.scheduled_encrypt_and_send,
            CronTrigger(hour=HOUR_TIME_PLAN, minute=MINUTE_TIME_PLAN),
            kwargs={"bot": application.bot},
            misfire_grace_time=300
        )
        scheduler.start()
        logging.info(f"✅ Планировщик запущен: архив будет отправляться ежедневно в {HOUR_TIME_PLAN}:{MINUTE_TIME_PLAN:02d}")





    def run(self):
        """Запуск бота"""
        if not self.bot_token:
            logging.info("❌ BOT_TOKEN не найден. Установите его в файле .env")
            return

        application = Application.builder().token(self.bot_token).post_init(self.post_init).build()
        application.add_handler(CommandHandler("start", self.start))
        application.add_handler(CallbackQueryHandler(self.button_handler))

        logging.info("Бот запущен...")
        application.run_polling()


if __name__ == "__main__":
    try:
        bot = DockerBot()
        bot.run()
    except Exception as e:
        logging.info(f"Критическая ошибка при запуске: {e}")
