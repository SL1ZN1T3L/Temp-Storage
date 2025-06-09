import os
import random
import sqlite3
import logging
import shutil
import time
import asyncio
import aiosqlite
from datetime import datetime, timedelta
from dotenv import load_dotenv
from telegram import Update, ReplyKeyboardMarkup, KeyboardButton
from telegram.ext import Application, CommandHandler, MessageHandler, ContextTypes, filters, ConversationHandler
import sys
import aiofiles

# Определяем путь к директории бота
BOT_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BOT_DIR, 'bot_users.db')
TEMP_DIR = os.path.join(BOT_DIR, 'temp')
LOG_DIR = os.path.join(BOT_DIR, 'logs')
TEMP_LINKS_DIR = os.path.join(BOT_DIR, 'temp_links')
Flag = False


# Создаем директории логов, если они не существуют
try:
    shutil.rmtree('logs')
    os.makedirs('logs')
except FileNotFoundError:
    os.makedirs('logs')

# Настройка логирования
logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(os.path.join(LOG_DIR, 'bot.log')),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

# Загрузка переменных окружения
load_dotenv()
TOKEN = os.getenv('BOT_TOKEN')
if not TOKEN:
    raise ValueError("Не указан токен бота в файле .env (BOT_TOKEN)")

COUNT_ID = int(os.getenv('COUNT_ID')) # Колличество символов link_id
if not COUNT_ID:
    raise ValueError('Не указано количество символов-ID хранилища в файле .env(COUNT_ID).')

ADMIN_CODE = os.getenv('ADMIN_CODE')
if not ADMIN_CODE:
    raise ValueError("Не указан код администратора в файле .env (ADMIN_CODE)")

USER_PLUS_CODE = os.getenv('USER_PLUS_CODE')
if not USER_PLUS_CODE:
    raise ValueError("Не указан код привилегированного пользователя в файле .env (USER_PLUS_CODE)")

TEMP_LINK_DOMAIN = os.getenv('TEMP_LINK_DOMAIN', 'https://your-domain.com')

# Константы
MAX_TEMP_LINK_HOURS = 720  # Максимальное время хранения файла в часах (30 дней)
SPAM_COOLDOWN = 0.5  # Минимальное время между действиями в секундах
MAX_ACTIONS_PER_MINUTE = 20  # Максимальное количество действий в минуту
BAN_THRESHOLD = 50  # Порог для автоматической блокировки
WARNING_THRESHOLD = 10  # Порог для предупреждения администратора
ADMIN_NOTIFICATION_INTERVAL = 60  # Интервал между уведомлениями администратора

# Состояния разговора
CAPTCHA, MENU, SETTINGS, TECH_COMMANDS, OTHER_COMMANDS, USER_MANAGEMENT, TEMP_LINK, TEMP_LINK_DURATION, TEMP_LINK_EXTEND, STORAGE_MANAGEMENT, BROADCAST = range(11)

# Роли пользователей
class UserRole:
    ADMIN = "admin"
    USER_PLUS = "user_plus"
    USER = "user"

# Глобальные переменные для защиты от спама
user_action_times = {}
user_action_counts = {}
user_spam_warnings = {}
user_ban_list = set()

async def ensure_directories():
    """Создание необходимых директорий с обработкой ошибок"""
    directories = [TEMP_DIR, LOG_DIR, TEMP_LINKS_DIR]
    for directory in directories:
        try:
            if not os.path.exists(directory):
                os.makedirs(directory)
                logger.info(f"Создана директория: {directory}")
                # Проверяем права на запись
                test_file = os.path.join(directory, 'test.txt')
                async with aiofiles.open(test_file, 'w') as f:
                    await f.write('test')
                os.remove(test_file)
                logger.info(f"Проверка прав доступа к директории {directory} успешна")
        except Exception as e:
            logger.error(f"Ошибка при создании директории {directory}: {e}")
            sys.exit(1)

async def log_error(user_id, error_message):
    """Логирование ошибок в файл"""
    try:
        log_file = os.path.join(LOG_DIR, f'error_{datetime.now().strftime("%Y-%m-%d")}.log')
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        async with aiofiles.open(log_file, 'a', encoding='utf-8') as f:
            await f.write(f"[{timestamp}] User {user_id}: {error_message}\n")
    except Exception as e:
        print(f"Ошибка при логировании: {str(e)}")
        print(f"[{timestamp}] User {user_id}: {error_message}")

async def setup_database():
    """Настройка базы данных"""
    async with aiosqlite.connect(DB_PATH) as conn:
        # Таблица users
        await conn.execute('''CREATE TABLE IF NOT EXISTS users
                 (user_id INTEGER PRIMARY KEY,
                  username TEXT,
                  is_verified BOOLEAN DEFAULT FALSE,
                  role TEXT DEFAULT 'user',
                  last_action_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                  is_banned BOOLEAN DEFAULT FALSE)''')
        
        # Проверка наличия поля is_banned
        cursor = await conn.execute("PRAGMA table_info(users)")
        columns = [column[1] for column in await cursor.fetchall()]
        if 'is_banned' not in columns:
            await conn.execute("ALTER TABLE users ADD COLUMN is_banned BOOLEAN DEFAULT FALSE")

        # Создание таблицы bot_status
        await conn.execute('''CREATE TABLE IF NOT EXISTS bot_status
                 (id INTEGER PRIMARY KEY,
                  status TEXT DEFAULT 'enabled',
                  lines_to_keep INTEGER DEFAULT 10)''')
        
        # Таблица temp_links
        await conn.execute('''CREATE TABLE IF NOT EXISTS temp_links
                 (link_id TEXT PRIMARY KEY,
                  user_id INTEGER,
                  expires_at TIMESTAMP,
                  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                  extension_count INTEGER DEFAULT 0,
                  FOREIGN KEY (user_id) REFERENCES users(user_id))''')

        # Проверяем наличие записи с id=1
        cursor = await conn.execute('SELECT COUNT(*) FROM bot_status WHERE id = 1')
        count = await cursor.fetchone()
        if count[0] == 0:
            await conn.execute('INSERT INTO bot_status (id, status, lines_to_keep) VALUES (1, "enabled", 10)')
        
        # Проверка наличия поля extension_count
        cursor = await conn.execute("PRAGMA table_info(temp_links)")
        columns = [column[1] for column in await cursor.fetchall()]
        if 'extension_count' not in columns:
            await conn.execute("ALTER TABLE temp_links ADD COLUMN extension_count INTEGER DEFAULT 0")
        
        # Таблица temp_link_files
        await conn.execute('''CREATE TABLE IF NOT EXISTS temp_link_files
                 (file_id TEXT PRIMARY KEY,
                  link_id TEXT,
                  file_path TEXT,
                  original_name TEXT,
                  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                  FOREIGN KEY (link_id) REFERENCES temp_links(link_id))''')
        
        await conn.commit()
    
    logger.info("База данных успешно инициализирована")

def is_user_verified(user_id):
    """Проверка верификации пользователя"""
    conn = sqlite3.connect(DB_PATH)
    try:
        c = conn.cursor()
        c.execute('SELECT is_verified FROM users WHERE user_id = ?', (user_id,))
        result = c.fetchone()
        return result[0] if result else False
    finally:
        conn.close()

def is_admin(user_id):
    """Проверка, является ли пользователь администратором"""
    conn = sqlite3.connect(DB_PATH)
    try:
        c = conn.cursor()
        c.execute('SELECT role FROM users WHERE user_id = ?', (user_id,))
        result = c.fetchone()
        return result and result[0] == UserRole.ADMIN
    finally:
        conn.close()

async def verify_user(user_id, username, role=UserRole.USER):
    """Верификация пользователя в базе данных"""
    async with aiosqlite.connect(DB_PATH) as conn:
        cursor = await conn.execute('SELECT role FROM users WHERE user_id = ?', (user_id,))
        result = await cursor.fetchone()
        
        if result:
            existing_role = result[0]
            if role == UserRole.USER:
                role = existing_role
        
        await conn.execute('''
            INSERT OR REPLACE INTO users 
            (user_id, username, is_verified, role)
            VALUES (?, ?, TRUE, ?)
        ''', (user_id, username, role))
        await conn.commit()

def is_bot_enabled():
    """Проверка, включен ли бот"""
    conn = sqlite3.connect(DB_PATH)
    try:
        c = conn.cursor()
        c.execute('SELECT status FROM bot_status WHERE id = 1')
        result = c.fetchone()
        return result[0] == 'enabled' if result else True
    finally:
        conn.close()

def generate_captcha():
    """Генерация простой математической капчи"""
    num1 = random.randint(1, 10)
    num2 = random.randint(1, 10)
    operation = random.choice(['+', '-', '*'])
    if operation == '+':
        answer = num1 + num2
    elif operation == '-':
        answer = num1 - num2
    else:
        answer = num1 * num2
    question = f"{num1} {operation} {num2} = ?"
    return question, str(answer)

def get_menu_keyboard(user_id):
    """Создание клавиатуры с меню"""
    keyboard = [
        ['🔗 Создать временное хранилище'],
        ['ℹ️ Помощь']
        ]
    if is_admin(user_id):
        keyboard.append([KeyboardButton(text='⚙️ Настройки')])
    return ReplyKeyboardMarkup(keyboard, resize_keyboard=True)

async def start(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not await check_user_access(update, context):
        return ConversationHandler.END
        
    user_id = update.effective_user.id
    username = update.effective_user.username
    
    args = context.args
    if args:
        command = args[0]
        if command.startswith('admin'):
            code = command[5:]
            if code == ADMIN_CODE:
                await verify_user(user_id, username, UserRole.ADMIN)
                await update.message.reply_text("Вы успешно авторизованы как администратор! 👑")
                return await show_menu(update, context)
            else:
                await update.message.reply_text("❌ Неверный код администратора.")
                return MENU
        elif command.startswith('user_plus'):
            code = command[9:]
            if code == USER_PLUS_CODE:
                await verify_user(user_id, username, UserRole.USER_PLUS)
                await update.message.reply_text("Вы успешно авторизованы как привилегированный пользователь! ⭐")
                return await show_menu(update, context)
            else:
                await update.message.reply_text("❌ Неверный код привилегированного пользователя.")
                return MENU
    
    if is_user_verified(user_id):
        return await show_menu(update, context)
    
    return await send_captcha(update, context)

async def send_captcha(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Отправка капчи пользователю"""
    question, answer = generate_captcha()
    context.user_data['captcha_answer'] = answer
    await update.message.reply_text(
        f"Для верификации, пожалуйста, решите пример:\n{question}"
    )
    return CAPTCHA

async def check_captcha(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Проверка ответа на капчу"""
    try:
        user_answer = update.message.text
        correct_answer = context.user_data.get('captcha_answer')
        
        if user_answer == correct_answer:
            await verify_user(
                update.effective_user.id,
                update.effective_user.username,
                UserRole.USER
            )
            await update.message.reply_text("Верификация успешно пройдена!")
            return await show_menu(update, context)
        else:
            await update.message.reply_text("Неверный ответ. Попробуйте еще раз.")
            return await send_captcha(update, context)
    except ValueError:
        await update.message.reply_text("Пожалуйста, введите число.")
        return await send_captcha(update, context)

async def show_menu(update: Update, context: ContextTypes.DEFAULT_TYPE):
    await update.message.reply_text(
        "Выберите действие:",
        reply_markup=get_menu_keyboard(update.effective_user.id)
    )
    return MENU

async def handle_menu(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not await check_user_access(update, context):
        return MENU
    
    if not is_bot_enabled() and not is_admin(update.effective_user.id):
        await update.message.reply_text("Бот находится на техническом обслуживании. Пожалуйста, подождите.")
        return MENU
        
    text = update.message.text
    
    if text == '🔗 Создать временное хранилище':
        try:
            conn = sqlite3.connect(DB_PATH)
            c = conn.cursor()
            c.execute('''
                SELECT link_id, expires_at 
                FROM temp_links 
                WHERE user_id = ? AND expires_at > datetime('now')
                ORDER BY created_at DESC
                LIMIT 1
            ''', (update.effective_user.id,))
            active_storage = c.fetchone()
            
            if active_storage:
                link_id, expires_at = active_storage
                storage_url = f"{TEMP_LINK_DOMAIN}/{link_id}"
                keyboard = [
                    [KeyboardButton("🗑️ Удалить хранилище"), KeyboardButton("🔄 Продлить срок хранилища")],
                    [KeyboardButton("Назад")]
                ]
                markup = ReplyKeyboardMarkup(keyboard, resize_keyboard=True)
                await update.message.reply_text(
                    f"У вас уже есть активное временное хранилище!\n\n"
                    f"🔗 Ссылка: {storage_url}\n"
                    f"⏱ Срок действия до: {format_datetime(expires_at)}\n\n"
                    f"Вы можете продолжать использовать это хранилище или удалить его.",
                    reply_markup=markup
                )
                context.user_data['current_storage'] = link_id
                return TEMP_LINK
            keyboard = [
                ['1 час', '6 часов'],
                ['12 часов', '24 часа'],
                ['3 дня', '7 дней'],
                ['14 дней', '30 дней'],
                ['Назад']
            ]
            await update.message.reply_text(
                "Выберите срок хранения временного хранилища:",
                reply_markup=ReplyKeyboardMarkup(keyboard, resize_keyboard=True)
            )
            return TEMP_LINK_DURATION
        except Exception as e:
            logger.error(f"Ошибка при проверке хранилища: {str(e)}")
            await update.message.reply_text(
                "Произошла ошибка при проверке хранилища. Попробуйте позже.",
                reply_markup=get_menu_keyboard(update.effective_user.id)
            )
            return MENU
        finally:
            if 'conn' in locals():
                conn.close()
    elif text == 'ℹ️ Помощь':
        await update.message.reply_text(
            "📚 *Помощь по использованию бота*\n\n"
            "🔗 *Создать временное хранилище* - создает хранилище для файлов с выбором срока хранения от 1 часа до 30 дней\n"
            "⚙️ *Настройки* - настройки бота (для администраторов)\n\n"
            "Для начала работы выберите нужную функцию в меню.",
            parse_mode='Markdown'
        )
        return MENU
    elif text == '⚙️ Настройки' and is_admin(update.effective_user.id):
        return await settings_command(update, context)
    
    return MENU

async def settings_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not is_bot_enabled() and not is_admin(update.effective_user.id):
        await update.message.reply_text("Бот находится на техническом обслуживании. Пожалуйста, подождите.")
        return MENU
    
    keyboard = []
    if is_admin(update.effective_user.id):
        keyboard.extend([
            [KeyboardButton(text="Технические команды")],
            [KeyboardButton(text="Другое")]
        ])
    keyboard.append([KeyboardButton(text="Назад")])
    markup = ReplyKeyboardMarkup(keyboard, resize_keyboard=True)
    await update.message.reply_text("Настройки:", reply_markup=markup)
    return SETTINGS

async def process_settings(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not is_bot_enabled() and not is_admin(update.effective_user.id):
        await update.message.reply_text("Бот находится на техническом обслуживании. Пожалуйста, подождите.")
        return MENU
    text = update.message.text
    
    if text == "Назад":
        await show_menu(update, context)
        return MENU
    elif text == "Технические команды" and is_admin(update.effective_user.id):
        markup = ReplyKeyboardMarkup(
            keyboard=[
                [KeyboardButton(text="Включить бота")],
                [KeyboardButton(text="Выключить бота")],
                [KeyboardButton(text="Перезапустить бота")],
                [KeyboardButton(text="Назад")]
            ],
            resize_keyboard=True
        )
        await update.message.reply_text("Технические команды:", reply_markup=markup)
        return TECH_COMMANDS
    elif text == "Другое" and is_admin(update.effective_user.id):
        markup = ReplyKeyboardMarkup(
            keyboard=[
                [KeyboardButton(text="Написать всем пользователям")],
                [KeyboardButton(text="Управление пользователями")],
                [KeyboardButton(text="Управление хранилищами")],
                [KeyboardButton(text="Назад")]
            ],
            resize_keyboard=True
        )
        await update.message.reply_text("Другое:", reply_markup=markup)
        return OTHER_COMMANDS
    else:
        await update.message.reply_text("Пожалуйста, выберите действие из меню.")
        return SETTINGS

async def process_tech_commands(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not await check_admin_rights(update.effective_user.id):
        await update.message.reply_text("У вас нет прав для выполнения этой команды.")
        await show_menu(update, context)
        return MENU
    if not is_bot_enabled() and not is_admin(update.effective_user.id):
        await update.message.reply_text("Бот находится на техническом обслуживании. Пожалуйста, подождите.")
        return MENU
    
    text = update.message.text
    
    if text == "Назад":
        await settings_command(update, context)
        return SETTINGS
    elif text == "Включить бота":
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        c.execute("UPDATE bot_status SET status='enabled' WHERE id=1")
        conn.commit()
        conn.close()
        await update.message.reply_text("Бот включен.")
    elif text == "Выключить бота":
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        c.execute("UPDATE bot_status SET status='disabled' WHERE id=1")
        conn.commit()
        conn.close()
        await update.message.reply_text("Бот выключен. Теперь он на техническом обслуживании.")
    elif text == "Перезапустить бота":
        await update.message.reply_text("Перезапуск бота...")
        # Отправляем сигнал SIGTERM для корректного завершения работы
        import os
        import signal
        logger.info("Перезапуск бота по команде администратора")
        os.kill(os.getpid(), signal.SIGTERM)
    
    return TECH_COMMANDS

async def process_other_commands(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not await check_admin_rights(update.effective_user.id):
        await update.message.reply_text("У вас нет прав для выполнения этой команды.")
        await show_menu(update, context)
        return MENU
    if not is_bot_enabled() and not is_admin(update.effective_user.id):
        await update.message.reply_text("Бот находится на техническом обслуживании. Пожалуйста, подождите.")
        return MENU
    
    text = update.message.text
    
    if text == "Назад":
        await settings_command(update, context)
        return SETTINGS
    elif text == "Написать всем пользователям":
        await update.message.reply_text("Введите сообщение для рассылки:")
        return BROADCAST
    elif text == "Управление пользователями":
        return await show_users_list(update, context)
    elif text == "Управление хранилищами":
        return await show_storage_list(update, context)
    else:
        await settings_command(update, context)
        return SETTINGS

async def broadcast_heandler(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not await check_admin_rights(update.effective_user.id):
        await update.message.reply_text("У вас нет прав для выполнения этой команды.")
        await show_menu(update, context)
        return MENU
    if not is_bot_enabled() and not is_admin(update.effective_user.id):
        await update.message.reply_text("Бот находится на техническом обслуживании. Пожалуйста, подождите.")
        return MENU
    
    text = update.message.text
    # Отправляем сообщение всем пользователям
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('SELECT user_id FROM users WHERE is_verified = TRUE')
    users = c.fetchall()
    conn.close()
    
    success_count = 0
    for user_id in users:
        try:
            await context.bot.send_message(chat_id=user_id[0], text=text)
            success_count += 1
        except Exception as e:
            print(f"Ошибка отправки сообщения пользователю {user_id[0]}: {e}")
    
    await update.message.reply_text(f"Сообщение отправлено {success_count} пользователям.")
    return OTHER_COMMANDS

async def show_users_list(update: Update, context: ContextTypes.DEFAULT_TYPE):
    users = await get_all_users_async()
    if not users:
        await update.message.reply_text("В базе данных нет пользователей.")
        return OTHER_COMMANDS
    
    verified_count = sum(1 for user in users if user[2])
    banned_count = sum(1 for user in users if user[7])
    
    user_list = f"Всего верифицированных пользователей: {verified_count}\n"
    user_list += f"Заблокированных пользователей: {banned_count}\n\nСписок пользователей:\n\n"
    
    keyboard = []
    users_dict = {}
    
    for user in users:
        user_id = user[0]
        username = user[1] or f"ID: {user_id}"
        role = 'Пользователь' if user[3]=='user' else 'Пользователь+' if user[3]=='user_plus' else 'Админ'
        is_banned = user[7]
        
        user_list += (
            f"ID: {user[0]}\n"
            f"Имя: {user[1] or 'Не указано'}\n"
            f"Верифицирован: {'Да' if user[2] else 'Нет'}\n"
            f"Роль: {role}\n"
            f"Статус: {'Заблокирован' if is_banned else 'Активен'}\n\n"
        )
        
        button_text = f"{username} ({role}){' [ЗАБЛОКИРОВАН]' if is_banned else ''}"
        keyboard.append([KeyboardButton(text=button_text)])
        users_dict[button_text] = user_id

    keyboard.append([KeyboardButton(text="Назад")])
    markup = ReplyKeyboardMarkup(keyboard, resize_keyboard=True)
    
    context.user_data['users_info'] = users_dict
    await update.message.reply_text(
        user_list + "\nВыберите пользователя для управления:", 
        reply_markup=markup
    )
    return USER_MANAGEMENT

async def process_user_management(update: Update, context: ContextTypes.DEFAULT_TYPE):
    text = update.message.text
    if text == "Назад":
        await settings_command(update, context)
        return SETTINGS
        
    if text in ["Убрать из базы", "Выдать пользователя", "Выдать пользователя+", "Выдать админа", "Заблокировать", "Разблокировать"]:
        user_id = context.user_data.get('selected_user_id')
        if not user_id:
            await update.message.reply_text("Сначала выберите пользователя.")
            return USER_MANAGEMENT
            
        if text == "Убрать из базы":
            if user_id == update.effective_user.id:
                await update.message.reply_text("Вы не можете удалить себя.")
            else:
                try:
                    await remove_user(user_id)
                    await update.message.reply_text("Пользователь удален.")
                    return await show_users_list(update, context)
                except Exception as e:
                    await update.message.reply_text(f"Ошибка при удалении пользователя: {str(e)}")
        elif text == "Заблокировать":
            if user_id == update.effective_user.id:
                await update.message.reply_text("Вы не можете заблокировать себя.")
            else:
                try:
                    if await ban_user(context.bot, user_id, True):
                        await update.message.reply_text("Пользователь заблокирован.")
                    else:
                        await update.message.reply_text("Ошибка при блокировке пользователя.")
                    return await show_users_list(update, context)
                except Exception as e:
                    await update.message.reply_text(f"Ошибка при блокировке пользователя: {str(e)}")
        elif text == "Разблокировать":
            try:
                if await ban_user(context.bot, user_id, False):
                    await update.message.reply_text("Пользователь разблокирован.")
                else:
                    await update.message.reply_text("Ошибка при разблокировке пользователя.")
                return await show_users_list(update, context)
            except Exception as e:
                await update.message.reply_text(f"Ошибка при разблокировке пользователя: {str(e)}")
        else:
            role = {
                "Выдать пользователя": UserRole.USER,
                "Выдать пользователя+": UserRole.USER_PLUS,
                "Выдать админа": UserRole.ADMIN
            }[text]
            
            try:
                async with aiosqlite.connect(DB_PATH) as conn:
                    await conn.execute('UPDATE users SET role = ? WHERE user_id = ?', (role, user_id))
                    await conn.commit()
                await update.message.reply_text("Роль пользователя обновлена.")
                return await show_users_list(update, context)
            except Exception as e:
                await update.message.reply_text(f"Ошибка при обновлении роли: {str(e)}")
    
    elif text in context.user_data.get('users_info', {}):
        user_id = context.user_data['users_info'][text]
        context.user_data['selected_user_id'] = user_id
        is_banned = is_user_banned(user_id)
        keyboard = [
            [KeyboardButton(text="Убрать из базы")],
            [KeyboardButton(text="Выдать пользователя")],
            [KeyboardButton(text="Выдать пользователя+")],
            [KeyboardButton(text="Выдать админа")],
            [KeyboardButton(text="Заблокировать" if not is_banned else "Разблокировать")],
            [KeyboardButton(text="Назад")]
        ]
        markup = ReplyKeyboardMarkup(keyboard, resize_keyboard=True)
        await update.message.reply_text(
            f"Выберите действие для пользователя {text}:",
            reply_markup=markup
        )
    
    return USER_MANAGEMENT

async def safe_db_connect():
    """Безопасное подключение к базе данных"""
    try:
        return await aiosqlite.connect(DB_PATH)
    except sqlite3.Error as e:
        print(f"Ошибка подключения к базе данных: {e}")
        return None

async def get_user_role(user_id):
    """Получение роли пользователя"""
    async with aiosqlite.connect(DB_PATH) as conn:
        cursor = await conn.execute('SELECT role FROM users WHERE user_id = ?', (user_id,))
        result = await cursor.fetchone()
    return result[0] if result else UserRole.USER

async def check_admin_rights(user_id):
    """Проверка прав администратора"""
    return await get_user_role(user_id) == UserRole.ADMIN

async def check_user_plus_rights(user_id):
    """Проверка прав привилегированного пользователя"""
    role = await get_user_role(user_id)
    return role in [UserRole.ADMIN, UserRole.USER_PLUS]

async def generate_temp_link_id():
    """Генерация уникального ID для временной ссылки"""
    chars = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789'
    while True:
        link_id = ''.join(random.choice(chars) for _ in range(COUNT_ID))
        async with aiosqlite.connect(DB_PATH) as conn:
            cursor = await conn.execute('SELECT COUNT(*) FROM temp_links WHERE link_id = ?', (link_id,))
            count = await cursor.fetchone()
            if count[0] == 0:
                return link_id

async def process_temp_link_duration(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if update.message.text == "Назад":
        await show_menu(update, context)
        return MENU
    
    duration_map = {
        '1 час': 1,
        '6 часов': 6,
        '12 часов': 12,
        '24 часа': 24,
        '3 дня': 72,
        '7 дней': 168,
        '14 дней': 336,
        '30 дней': 720
    }
    
    if update.message.text not in duration_map:
        await update.message.reply_text(
            "Пожалуйста, выберите срок хранения из предложенных вариантов."
        )
        return TEMP_LINK_DURATION
    
    try:
        storage_list = await get_user_active_storage(update.effective_user.id)
        if storage_list:
            storage = storage_list[0]
            storage_url = f"{TEMP_LINK_DOMAIN}/{storage['link_id']}"
            keyboard = [
                [KeyboardButton("🗑️ Удалить хранилище"), KeyboardButton("🔄 Продлить срок хранилища")],
                [KeyboardButton("Назад")]
            ]
            markup = ReplyKeyboardMarkup(keyboard, resize_keyboard=True)
            await update.message.reply_text(
                f"У вас уже есть активное временное хранилище!\n\n"
                f"🔗 Ссылка: {storage_url}\n"
                f"⏱ Срок действия до: {format_datetime(storage['expires_at'])}\n\n"
                f"Вы можете продолжать использовать это хранилище или удалить его.",
                reply_markup=markup
            )
            context.user_data['current_storage'] = storage['link_id']
            return TEMP_LINK
            
        duration_hours = duration_map[update.message.text]
        link_id = await generate_temp_link_id()
        expires_at = datetime.now() + timedelta(hours=duration_hours)
        
        async with aiosqlite.connect(DB_PATH) as conn:
            await conn.execute('''
                INSERT INTO temp_links (link_id, expires_at, user_id, created_at, extension_count)
                VALUES (?, ?, ?, datetime('now'), 0)
            ''', (link_id, expires_at, update.effective_user.id))
            await conn.commit()
        
        storage_url = f"{TEMP_LINK_DOMAIN}/{link_id}"
        keyboard = [
            [KeyboardButton("🗑️ Удалить хранилище"), KeyboardButton("🔄 Продлить срок хранилища")],
            [KeyboardButton("Назад")]
        ]
        markup = ReplyKeyboardMarkup(keyboard, resize_keyboard=True)
        
        duration_text = ""
        if duration_hours < 24:
            duration_text = f"{duration_hours} {'час' if duration_hours == 1 else 'часа' if 1 < duration_hours < 5 else 'часов'}"
        elif duration_hours < 48:
            duration_text = "1 день"
        else:
            days = duration_hours // 24
            duration_text = f"{days} {'день' if days == 1 else 'дня' if 1 < days < 5 else 'дней'}"
            
        await update.message.reply_text(
            f"✅ Временное хранилище создано!\n\n"
            f"🔗 Ссылка: {storage_url}\n"
            f"⏱ Срок действия: {duration_text}\n\n"
            f"⚠️ Хранилище будет доступно до {format_datetime(expires_at)}\n\n"
            f"Вы можете загружать файлы через веб-интерфейс.",
            reply_markup=markup
        )
        
        context.user_data['current_storage'] = link_id
        return TEMP_LINK
            
    except Exception as e:
        logger.error(f"Ошибка при создании временного хранилища: {str(e)}")
        await update.message.reply_text(
            "Произошла ошибка при создании временного хранилища. Попробуйте снова.",
            reply_markup=get_menu_keyboard(update.effective_user.id)
        )
        return MENU

async def extend_storage_duration(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if update.message.text == "Назад":
        link_id = context.user_data.get('extend_storage')
        if link_id:
            keyboard = [
                [KeyboardButton("🗑️ Удалить хранилище"), KeyboardButton("🔄 Продлить срок хранилища")],
                [KeyboardButton("Назад")]
            ]
            markup = ReplyKeyboardMarkup(keyboard, resize_keyboard=True)
            conn = sqlite3.connect(DB_PATH)
            c = conn.cursor()
            c.execute('SELECT expires_at FROM temp_links WHERE link_id = ? AND user_id = ?', 
                     (link_id, update.effective_user.id))
            result = c.fetchone()
            if not result:
                await update.message.reply_text(
                    "Хранилище не найдено или уже удалено.", 
                    reply_markup=get_menu_keyboard(update.effective_user.id)
                )
                conn.close()
                return MENU
            expires_at = result[0]
            storage_url = f"{TEMP_LINK_DOMAIN}/{link_id}"
            await update.message.reply_text(
                f"У вас есть активное временное хранилище!\n\n"
                f"🔗 Ссылка: {storage_url}\n"
                f"⏱ Срок действия до: {format_datetime(expires_at)}\n\n"
                f"Выберите действие:",
                reply_markup=markup
            )
            conn.close()
            return TEMP_LINK
        await show_menu(update, context)
        return MENU
    
    duration_map = {
        '1 час': 1,
        '6 часов': 6,
        '12 часов': 12,
        '24 часа': 24,
        '3 дня': 72,
        '7 дней': 168,
        '14 дней': 336,
        '30 дней': 720
    }
    
    if update.message.text not in duration_map:
        await update.message.reply_text(
            "Пожалуйста, выберите срок продления из предложенных вариантов."
        )
        return TEMP_LINK_EXTEND
    
    try:
        link_id = context.user_data.get('extend_storage')
        if not link_id:
            await update.message.reply_text(
                "Не найдено активное хранилище для продления.", 
                reply_markup=get_menu_keyboard(update.effective_user.id)
            )
            return MENU
            
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        c.execute('SELECT expires_at, extension_count FROM temp_links WHERE link_id = ? AND user_id = ?', 
                 (link_id, update.effective_user.id))
        result = c.fetchone()
        
        if not result:
            await update.message.reply_text(
                "Хранилище не найдено или уже удалено.", 
                reply_markup=get_menu_keyboard(update.effective_user.id)
            )
            conn.close()
            return MENU
            
        expires_at, extension_count = result
        extension_count = extension_count or 0
        max_extensions = 1
        if extension_count >= max_extensions:
            await update.message.reply_text(
                f"Достигнут лимит продлений хранилища (максимум {max_extensions}). Создайте новое хранилище.", 
                reply_markup=get_menu_keyboard(update.effective_user.id)
            )
            conn.close()
            return MENU
            
        current_expires_at = datetime.strptime(format_datetime(expires_at), '%Y-%m-%d %H:%M:%S')
        if current_expires_at <= datetime.now():
            await update.message.reply_text(
                "Срок действия хранилища уже истек. Создайте новое хранилище.", 
                reply_markup=get_menu_keyboard(update.effective_user.id)
            )
            conn.close()
            return MENU
            
        duration_hours = duration_map[update.message.text]
        new_expires_at = current_expires_at + timedelta(hours=duration_hours)
        
        c.execute('UPDATE temp_links SET expires_at = ?, extension_count = extension_count + 1 WHERE link_id = ?', 
                 (new_expires_at, link_id))
        conn.commit()
        
        duration_text = ""
        if duration_hours < 24:
            duration_text = f"{duration_hours} {'час' if duration_hours == 1 else 'часа' if 1 < duration_hours < 5 else 'часов'}"
        elif duration_hours < 48:
            duration_text = "1 день"
        else:
            days = duration_hours // 24
            duration_text = f"{days} {'день' if days == 1 else 'дня' if 1 < days < 5 else 'дней'}"
        
        keyboard = [
            [KeyboardButton("🗑️ Удалить хранилище"), KeyboardButton("🔄 Продлить срок хранилища")],
            [KeyboardButton("Назад")]
        ]
        markup = ReplyKeyboardMarkup(keyboard, resize_keyboard=True)
        storage_url = f"{TEMP_LINK_DOMAIN}/{link_id}"
        
        await update.message.reply_text(
            f"✅ Срок действия хранилища успешно продлен на {duration_text}!\n\n"
            f"🔗 Ссылка: {storage_url}\n"
            f"⏱ Новый срок действия до: {format_datetime(new_expires_at)}\n"
            f"🔄 Осталось продлений: {max_extensions - (extension_count + 1)}\n\n"
            f"Выберите действие:",
            reply_markup=markup
        )
        
        context.user_data['current_storage'] = link_id
        if 'extend_storage' in context.user_data:
            del context.user_data['extend_storage']
        
        return TEMP_LINK
        
    except Exception as e:
        if 'conn' in locals():
            conn.rollback()
        logger.error(f"Ошибка при продлении срока хранилища: {str(e)}")
        await update.message.reply_text(
            "Произошла ошибка при продлении срока хранилища. Попробуйте снова.",
            reply_markup=get_menu_keyboard(update.effective_user.id)
        )
        return MENU
    finally:
        if 'conn' in locals():
            conn.close()

async def delete_user_storage(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if update.message.text == "Назад":
        await show_menu(update, context)
        return MENU
    
    if update.message.text == "🔄 Продлить срок хранилища":
        link_id = context.user_data.get('current_storage')
        if not link_id:
            await update.message.reply_text(
                "Не найдено активное хранилище для продления.", 
                reply_markup=get_menu_keyboard(update.effective_user.id)
            )
            return MENU
        keyboard = [
            ['1 час', '6 часов'],
            ['12 часов', '24 часа'],
            ['3 дня', '7 дней'],
            ['14 дней', '30 дней'],
            ['Назад']
        ]
        await update.message.reply_text(
            "Выберите срок, на который хотите продлить хранилище:",
            reply_markup=ReplyKeyboardMarkup(keyboard, resize_keyboard=True)
        )
        context.user_data['extend_storage'] = link_id
        return TEMP_LINK_EXTEND
    
    if update.message.text != "🗑️ Удалить хранилище":
        await show_menu(update, context)
        return MENU
    
    link_id = context.user_data.get('current_storage')
    if not link_id:
        await update.message.reply_text(
            "Не найдено активное хранилище для удаления.", 
            reply_markup=get_menu_keyboard(update.effective_user.id)
        )
        return MENU
    
    try:
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        c.execute('''
            SELECT link_id FROM temp_links 
            WHERE link_id = ? AND user_id = ?
        ''', (link_id, update.effective_user.id))
        
        if not c.fetchone():
            await update.message.reply_text(
                "Хранилище не найдено или уже удалено.", 
                reply_markup=get_menu_keyboard(update.effective_user.id)
            )
            return MENU
        
        storage_path = os.path.join(BOT_DIR, 'temp_storage', link_id)
        if os.path.exists(storage_path):
            shutil.rmtree(storage_path)
        
        c.execute('DELETE FROM temp_links WHERE link_id = ?', (link_id,))
        conn.commit()
        
        await update.message.reply_text(
            "✅ Хранилище успешно удалено!", 
            reply_markup=get_menu_keyboard(update.effective_user.id)
        )
        del context.user_data['current_storage']
        return MENU
        
    except Exception as e:
        if 'conn' in locals():
            conn.rollback()
        logger.error(f"Ошибка при удалении хранилища: {str(e)}")
        await update.message.reply_text(
            "Произошла ошибка при удалении хранилища. Попробуйте снова.",
            reply_markup=get_menu_keyboard(update.effective_user.id)
        )
        return MENU
    finally:
        if 'conn' in locals():
            conn.close()

async def cleanup_expired_links(context=None):
    """Очистка истекших временных ссылок"""
    try:
        if not os.path.exists(TEMP_LINKS_DIR):
            os.makedirs(TEMP_LINKS_DIR)
            logger.info(f"Создана директория для временных ссылок: {TEMP_LINKS_DIR}")
        
        import pytz
        moscow_tz = pytz.timezone('Europe/Moscow')
        now = datetime.now(moscow_tz)
        current_time = now.strftime('%Y-%m-%d %H:%M:%S')
        
        async with aiosqlite.connect(DB_PATH) as conn:
            cursor = await conn.execute('SELECT link_id, expires_at FROM temp_links')
            all_links = await cursor.fetchall()
            
            expired_links = []
            for link in all_links:
                link_id, expires_at = link
                clean_expires_at = expires_at.split('.')[0] if '.' in expires_at else expires_at
                if clean_expires_at <= current_time:
                    expired_links.append(link_id)
                    storage_path = os.path.join(BOT_DIR, 'temp_storage', link_id)
                    if os.path.exists(storage_path):
                        shutil.rmtree(storage_path)
            
            if expired_links:
                await conn.execute('DELETE FROM temp_links WHERE link_id IN ({})'.format(
                    ','.join('?' for _ in expired_links)), expired_links)
                await conn.commit()
                logger.info(f"Удалено {len(expired_links)} истекших хранилищ")
    
    except Exception as e:
        logger.error(f"Критическая ошибка при очистке истекших ссылок: {str(e)}")

async def get_user_active_storage(user_id, settings_flag=False):
    """Получение активных временных ссылок пользователя"""
    try:
        import pytz
        moscow_tz = pytz.timezone('Europe/Moscow')
        now = datetime.now(moscow_tz)
        current_time = now.strftime('%Y-%m-%d %H:%M:%S')
        
        async with aiosqlite.connect(DB_PATH) as conn:
            if is_admin(user_id) and settings_flag:
                cursor = await conn.execute('''
                    SELECT tl.link_id, tl.expires_at, COUNT(tlf.file_id) as file_count, tl.user_id, u.username
                    FROM temp_links tl
                    LEFT JOIN temp_link_files tlf ON tl.link_id = tlf.link_id
                    LEFT JOIN users u ON tl.user_id = u.user_id
                    GROUP BY tl.link_id
                    ORDER BY tl.expires_at ASC
                ''')
            else:
                cursor = await conn.execute('''
                    SELECT tl.link_id, tl.expires_at, COUNT(tlf.file_id) as file_count, tl.user_id, u.username
                    FROM temp_links tl
                    LEFT JOIN temp_link_files tlf ON tl.link_id = tlf.link_id
                    LEFT JOIN users u ON tl.user_id = u.user_id
                    WHERE tl.user_id = ?
                    GROUP BY tl.link_id
                    ORDER BY tl.expires_at ASC
                ''', (user_id,))
            result = await cursor.fetchall()
            
            storage_list = []
            for link_id, expires_at, file_count, creator_id, creator_username in result:
                clean_expires_at = expires_at.split('.')[0] if '.' in expires_at else expires_at
                if clean_expires_at <= current_time:
                    continue
                
                cursor = await conn.execute('''
                    SELECT original_name 
                    FROM temp_link_files 
                    WHERE link_id = ?
                ''', (link_id,))
                files = await cursor.fetchall()
                file_names = [file[0] for file in files]
                
                expires_date = datetime.strptime(clean_expires_at, '%Y-%m-%d %H:%M:%S')
                time_left = expires_date - now.replace(tzinfo=None)
                days = time_left.days
                hours, remainder = divmod(time_left.seconds, 3600)
                minutes, _ = divmod(remainder, 60)
                time_str = f"{days}д {hours}ч {minutes}м" if days > 0 else f"{hours}ч {minutes}м"
                
                creator_name = creator_username or f"ID: {creator_id}"
                storage_list.append({
                    'link_id': link_id,
                    'expires_at': clean_expires_at,
                    'file_count': file_count,
                    'file_names': file_names,
                    'time_left': time_str,
                    'creator_id': creator_id,
                    'creator_name': creator_name
                })
            
            return storage_list
    except Exception as e:
        logger.error(f"Ошибка при получении списка хранилища: {e}")
        return []

def format_datetime(dt):
    """Форматирование даты без миллисекунд"""
    if isinstance(dt, str):
        if '.' in dt:
            dt = dt.split('.')[0]
        return dt
    return dt.strftime('%Y-%m-%d %H:%M:%S')

async def show_storage_list(update: Update, context: ContextTypes.DEFAULT_TYPE):
    storage_list = await get_user_active_storage(update.effective_user.id, settings_flag=True)
    if not storage_list:
        await update.message.reply_text(
            "Активных хранилищ не найдено.",
            reply_markup=ReplyKeyboardMarkup([['Назад']], resize_keyboard=True)
        )
        return STORAGE_MANAGEMENT
    
    keyboard = []
    storage_info = {}
    
    for storage in storage_list:
        link_id = storage['link_id']
        expires_at = storage['expires_at']
        file_count = storage['file_count']
        time_left = storage['time_left']
        creator_name = storage['creator_name']
        
        async with aiosqlite.connect(DB_PATH) as conn:
            cursor = await conn.execute('SELECT extension_count FROM temp_links WHERE link_id = ?', 
                                      (link_id,))
            result = await cursor.fetchone()
            extension_count = result[0] if result and result[0] is not None else 0
            max_extensions = 1
            extensions_left = max_extensions - extension_count
        
        storage_text = f"Хранилище {link_id[:8]} ({file_count} файлов, {time_left}) от {creator_name}"
        keyboard.append([KeyboardButton(text=storage_text)])
        storage_info[storage_text] = {
            'link_id': link_id,
            'expires_at': expires_at,
            'file_names': storage['file_names'],
            'creator_name': creator_name,
            'creator_id': storage['creator_id'],
            'extensions_left': extensions_left
        }
    
    keyboard.append([KeyboardButton(text="Назад")])
    markup = ReplyKeyboardMarkup(keyboard, resize_keyboard=True)
    context.user_data['storage_info'] = storage_info
    await update.message.reply_text(
        "Выберите хранилище для управления:",
        reply_markup=markup
    )
    return STORAGE_MANAGEMENT

async def process_storage_management(update: Update, context: ContextTypes.DEFAULT_TYPE):
    text = update.message.text
    if text == "Назад":
        await settings_command(update, context)
        return SETTINGS
    
    storage_info = context.user_data.get('storage_info', {})
    if text in storage_info:
        storage_data = storage_info[text]
        context.user_data['selected_storage'] = storage_data
        keyboard = [
            [KeyboardButton(text="🗑️ Удалить хранилище")],
            [KeyboardButton(text="🔄 Продлить срок")],
            [KeyboardButton(text="Назад")]
        ]
        markup = ReplyKeyboardMarkup(keyboard, resize_keyboard=True)
        await update.message.reply_text(
            f"Управление хранилищем:\n\n"
            f"🔗 ID: {storage_data['link_id']}\n"
            f"👤 Создатель: {storage_data['creator_name']}\n"
            f"⏱ Срок действия до: {format_datetime(storage_data['expires_at'])}\n"
            f"🔄 Осталось продлений: {storage_data.get('extensions_left', 0)}\n\n"
            f"Выберите действие:",
            reply_markup=markup
        )
        return STORAGE_MANAGEMENT
    
    elif text == "🗑️ Удалить хранилище":
        storage_data = context.user_data.get('selected_storage')
        if not storage_data:
            await update.message.reply_text("Сначала выберите хранилище.")
            return await show_storage_list(update, context)
        
        try:
            storage_path = os.path.join(BOT_DIR, 'temp_storage', storage_data['link_id'])
            if os.path.exists(storage_path):
                shutil.rmtree(storage_path)
            
            async with aiosqlite.connect(DB_PATH) as conn:
                await conn.execute('DELETE FROM temp_links WHERE link_id = ?', (storage_data['link_id'],))
                await conn.commit()
            
            await update.message.reply_text(
                "✅ Хранилище успешно удалено!",
                reply_markup=ReplyKeyboardMarkup([['Назад']], resize_keyboard=True)
            )
            if 'selected_storage' in context.user_data:
                del context.user_data['selected_storage']
            return await show_storage_list(update, context)
            
        except Exception as e:
            logger.error(f"Ошибка при удалении хранилища: {str(e)}")
            await update.message.reply_text(
                "Произошла ошибка при удалении хранилища.",
                reply_markup=ReplyKeyboardMarkup([['Назад']], resize_keyboard=True)
            )
            return STORAGE_MANAGEMENT
    
    elif text == "🔄 Продлить срок":
        storage_data = context.user_data.get('selected_storage')
        if not storage_data:
            await update.message.reply_text("Сначала выберите хранилище.")
            return await show_storage_list(update, context)
        
        keyboard = [
            ['1 час', '6 часов'],
            ['12 часов', '24 часа'],
            ['3 дня', '7 дней'],
            ['14 дней', '30 дней'],
            ['Назад']
        ]
        await update.message.reply_text(
            "Выберите срок, на который хотите продлить хранилище:",
            reply_markup=ReplyKeyboardMarkup(keyboard, resize_keyboard=True)
        )
        return STORAGE_MANAGEMENT
    
    elif text in ['1 час', '6 часов', '12 часов', '24 часа', '3 дня', '7 дней', '14 дней', '30 дней']:
        storage_data = context.user_data.get('selected_storage')
        if not storage_data:
            await update.message.reply_text("Сначала выберите хранилище.")
            return await show_storage_list(update, context)
        
        duration_map = {
            '1 час': 1,
            '6 часов': 6,
            '12 часов': 12,
            '24 часа': 24,
            '3 дня': 72,
            '7 дней': 168,
            '14 дней': 336,
            '30 дней': 720
        }
        
        try:
            duration_hours = duration_map[text]
            async with aiosqlite.connect(DB_PATH) as conn:
                cursor = await conn.execute('SELECT extension_count FROM temp_links WHERE link_id = ?', 
                                         (storage_data['link_id'],))
                result = await cursor.fetchone()
                extension_count = result[0] if result and result[0] is not None else 0
                max_extensions = 1
                if extension_count >= max_extensions:
                    await update.message.reply_text(
                        f"Достигнут лимит продлений хранилища ({max_extensions}). Создайте новое хранилище.",
                        reply_markup=ReplyKeyboardMarkup([['Назад']], resize_keyboard=True)
                    )
                    return STORAGE_MANAGEMENT
                
                expires_dt = datetime.now() + timedelta(hours=duration_hours)
                new_expires_at = expires_dt.strftime('%Y-%m-%d %H:%M:%S')
                
                await conn.execute('UPDATE temp_links SET expires_at = ?, extension_count = extension_count + 1 WHERE link_id = ?', 
                                 (new_expires_at, storage_data['link_id']))
                await conn.commit()
            
            duration_text = ""
            if duration_hours < 24:
                duration_text = f"{duration_hours} {'час' if duration_hours == 1 else 'часа' if 1 < duration_hours < 5 else 'часов'}"
            elif duration_hours < 48:
                duration_text = "1 день"
            else:
                days = duration_hours // 24
                duration_text = f"{days} {'день' if days == 1 else 'дня' if 1 < days < 5 else 'дней'}"
            
            await update.message.reply_text(
                f"✅ Срок действия хранилища успешно продлен на {duration_text}!\n\n"
                f"⏱ Новый срок действия до: {new_expires_at}\n"
                f"🔄 Осталось продлений: {max_extensions - (extension_count + 1)}",
                reply_markup=ReplyKeyboardMarkup([['Назад']], resize_keyboard=True)
            )
            return await show_storage_list(update, context)
            
        except Exception as e:
            logger.error(f"Ошибка при продлении срока хранилища: {str(e)}")
            await update.message.reply_text(
                "Произошла ошибка при продлении срока хранилища.",
                reply_markup=ReplyKeyboardMarkup([['Назад']], resize_keyboard=True)
            )
            return STORAGE_MANAGEMENT
    
    return STORAGE_MANAGEMENT

def is_user_banned(user_id):
    conn = sqlite3.connect(DB_PATH)
    try:
        c = conn.cursor()
        c.execute('SELECT is_banned FROM users WHERE user_id = ?', (user_id,))
        result = c.fetchone()
        return result[0] if result else False
    finally:
        conn.close()

async def ban_user(bot, user_id, ban=True):
    try:
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        c.execute('UPDATE users SET is_banned = ? WHERE user_id = ?', (ban, user_id))
        conn.commit()
        if ban:
            user_ban_list.add(user_id)
        else:
            user_ban_list.discard(user_id)
        logger.info(f"Пользователь {user_id} {'заблокирован' if ban else 'разблокирован'}")
        return True
    except Exception as e:
        logger.error(f"Ошибка при блокировке/разблокировке пользователя {user_id}: {e}")
        return False
    finally:
        conn.close()

async def check_action_cooldown(user_id):
    current_time = time.time()
    if user_id not in user_action_times:
        user_action_times[user_id] = current_time
        user_action_counts[user_id] = 1
        return True
    
    last_action_time = user_action_times[user_id]
    time_diff = current_time - last_action_time
    
    if time_diff < 2:
        user_action_counts[user_id] = user_action_counts.get(user_id, 0) + 1
        if user_action_counts[user_id] > 5:
            user_spam_warnings[user_id] = user_spam_warnings.get(user_id, 0) + 1
            if user_spam_warnings[user_id] > 3:
                user_ban_list.add(user_id)
                async with aiosqlite.connect(DB_PATH) as conn:
                    await conn.execute('UPDATE users SET is_banned = 1 WHERE user_id = ?', (user_id,))
                    await conn.commit()
                logger.warning(f"Пользователь {user_id} заблокирован за спам")
                return False
            logger.warning(f"Обнаружена попытка спама от пользователя {user_id}")
            return False
    
    user_action_times[user_id] = current_time
    if time_diff > 10:
        user_action_counts[user_id] = 1
    return True

async def cleanup_spam_protection(context=None):
    current_time = time.time()
    for user_id in list(user_action_times.keys()):
        if current_time - user_action_times[user_id] > 300:
            del user_action_times[user_id]
            if user_id in user_action_counts:
                del user_action_counts[user_id]
            if user_id in user_spam_warnings:
                del user_spam_warnings[user_id]

async def check_user_access(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user_id = update.effective_user.id
    if user_id in user_ban_list:
        return False
    if is_user_banned(user_id):
        user_ban_list.add(user_id)
        return False
    if is_admin(user_id):
        return True
    if not await check_action_cooldown(user_id):
        await update.message.reply_text(
            "Слишком много запросов. Пожалуйста, подождите..."
        )
        return False
    return True

async def get_all_users_async():
    async with aiosqlite.connect(DB_PATH) as conn:
        cursor = await conn.execute('''SELECT user_id, username, is_verified, role, 
                 0, 0, 0, is_banned FROM users''')
        users = await cursor.fetchall()
    return users

async def remove_user(user_id):
    async with aiosqlite.connect(DB_PATH) as conn:
        await conn.execute('DELETE FROM users WHERE user_id = ?', (user_id,))
        await conn.commit()

if __name__ == '__main__':
    try:
        print("Запуск бота...")
        app = Application.builder().token(TOKEN).build()
        
        try:
            loop = asyncio.get_event_loop()
            if loop.is_closed():
                loop = asyncio.new_event_loop()
                asyncio.set_event_loop(loop)
            loop.run_until_complete(ensure_directories())
            loop.run_until_complete(setup_database())
        except Exception as e:
            print(f"Ошибка при настройке цикла событий: {e}")
            raise
        
        app.job_queue.run_repeating(cleanup_expired_links, interval=3600, first=10)
        app.job_queue.run_repeating(cleanup_spam_protection, interval=300, first=300)
        
        async def restore_menu(update: Update, context: ContextTypes.DEFAULT_TYPE):
            if not await check_user_access(update, context):
                return ConversationHandler.END
            if is_user_verified(update.effective_user.id):
                await show_menu(update, context)
                return MENU
            await update.message.reply_text("Пожалуйста, используйте команду /start для начала работы.")
            return ConversationHandler.END
        
        conv_handler = ConversationHandler(
            entry_points=[
                CommandHandler('start', start),
                MessageHandler(filters.TEXT & ~filters.COMMAND, restore_menu),
                MessageHandler(filters.Document.ALL, restore_menu)
            ],
            states={
                CAPTCHA: [MessageHandler(filters.TEXT & ~filters.COMMAND, check_captcha)],
                MENU: [MessageHandler(filters.TEXT & ~filters.COMMAND | filters.Document.ALL, handle_menu)],
                SETTINGS: [MessageHandler(filters.TEXT & ~filters.COMMAND, process_settings)],
                TECH_COMMANDS: [MessageHandler(filters.TEXT & ~filters.COMMAND, process_tech_commands)],
                OTHER_COMMANDS: [MessageHandler(filters.TEXT & ~filters.COMMAND, process_other_commands)],
                USER_MANAGEMENT: [MessageHandler(filters.TEXT & ~filters.COMMAND, process_user_management)],
                TEMP_LINK: [MessageHandler(filters.TEXT & ~filters.COMMAND | filters.Document.ALL, delete_user_storage)],
                TEMP_LINK_DURATION: [MessageHandler(filters.TEXT & ~filters.COMMAND, process_temp_link_duration)],
                TEMP_LINK_EXTEND: [MessageHandler(filters.TEXT & ~filters.COMMAND, extend_storage_duration)],
                STORAGE_MANAGEMENT: [MessageHandler(filters.TEXT & ~filters.COMMAND, process_storage_management)],
                BROADCAST: [MessageHandler(filters.TEXT & ~filters.COMMAND, broadcast_heandler)],
            },
            fallbacks=[
                CommandHandler('start', start),
                MessageHandler(filters.TEXT & ~filters.COMMAND, restore_menu),
                MessageHandler(filters.Document.ALL, restore_menu)
            ]
        )
        
        app.add_handler(conv_handler)
        
        print(f"Бот запущен и готов к работе!")
        print(f"База данных: {DB_PATH}")
        print(f"Временные файлы: {TEMP_DIR}")
        print(f"Логи: {LOG_DIR}")
        print(f"Временные ссылки: {TEMP_LINKS_DIR}")

        # Запускаем бота через asyncio для правильной обработки остановки
        loop = asyncio.get_event_loop()
        
        loop.run_until_complete(app.initialize())
        loop.run_until_complete(app.updater.initialize())
        loop.run_until_complete(app.start())
        loop.run_until_complete(app.updater.start_polling(allowed_updates=Update.ALL_TYPES))
        
        try:
            loop.run_forever()
        except (KeyboardInterrupt, SystemExit):
            loop.run_until_complete(app.stop())
            loop.run_until_complete(app.shutdown())
        
        print("Бот остановлен.")
        
    except (KeyboardInterrupt, SystemExit):
        print("Бот остановлен пользователем или системой.")
    except Exception as e:
        print(f"Критическая ошибка при запуске бота: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)