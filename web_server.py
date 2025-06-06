from flask import Flask, send_file, request, render_template, jsonify, session, redirect, url_for, send_from_directory
from flask_session import Session
import sqlite3
import aiosqlite
import asyncio
import os
import logging
from datetime import datetime, timedelta
import shutil
import secrets
from werkzeug.utils import secure_filename
import threading
import time
import tempfile
import zipfile
from io import BytesIO
from functools import wraps
import pytz
import re
from dotenv import load_dotenv
import html
import hashlib
from collections import defaultdict
import traceback  # Добавляем импорт traceback
from urllib.parse import unquote  # Добавляем unquote
import math  # Добавляем импорт math

# Загружаем переменные окружения из .env файла
from dotenv import load_dotenv
load_dotenv()

# Функция для выполнения асинхронных задач в синхронном контексте Flask
def run_async(func):
    """Декоратор для запуска асинхронных функций в синхронном контексте Flask"""
    @wraps(func)
    def wrapper(*args, **kwargs):
        loop = asyncio.new_event_loop()
        try:
            return loop.run_until_complete(func(*args, **kwargs))
        finally:
            loop.close()
    return wrapper

# Создаем необходимые директории
os.makedirs('logs', exist_ok=True)

# Настройка логирования
logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(os.path.join('logs', 'web.log')),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

# Пути к файлам и директориям
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
TEMPLATE_DIR = os.path.join(BASE_DIR, 'templates')
STATIC_DIR = os.path.join(BASE_DIR, 'web', 'static')  # Добавляем путь к статическим файлам
DB_PATH = os.path.join(BASE_DIR, 'bot_users.db')
TEMP_STORAGE_DIR = os.path.join(BASE_DIR, 'temp_storage')

app = Flask(__name__, template_folder=TEMPLATE_DIR, static_folder=STATIC_DIR)

# Добавляем конфигурацию для статических файлов
STATIC_FOLDER = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'web', 'static')
app.static_folder = STATIC_FOLDER
app.static_url_path = '/static'

# Загрузка конфигурации из .env файла
# Общий лимит хранилища (по умолчанию 500 MB)
MAX_STORAGE_SIZE_MB = int(os.getenv('MAX_STORAGE_SIZE_MB', 500))
app.config['MAX_STORAGE_SIZE'] = MAX_STORAGE_SIZE_MB * 1024 * 1024

# Максимальный размер загружаемого файла (по умолчанию 500 MB)
MAX_FILE_SIZE_MB = int(os.getenv('MAX_FILE_SIZE_MB', 500))
app.config['MAX_FILE_SIZE'] = MAX_FILE_SIZE_MB * 1024 * 1024

# Максимальное количество файлов в хранилище (по умолчанию не ограничено)
MAX_FILES_PER_STORAGE = int(os.getenv('MAX_FILES_PER_STORAGE', 0))
app.config['MAX_FILES_PER_STORAGE'] = MAX_FILES_PER_STORAGE

# Директория для временного хранилища
app.config['UPLOAD_FOLDER'] = os.getenv('UPLOAD_FOLDER', 'temp_storage')

# Разрешенные типы файлов (расширения, белый список)
DEFAULT_ALLOWED_EXTENSIONS = 'txt,pdf,png,jpg,jpeg,gif,doc,docx,xls,xlsx,ppt,pptx,zip,rar,7z,mp3,mp4,avi,mov,mkv'
ALLOWED_EXTENSIONS_STRING = os.getenv('ALLOWED_EXTENSIONS', DEFAULT_ALLOWED_EXTENSIONS)
app.config['ALLOWED_EXTENSIONS'] = set(ALLOWED_EXTENSIONS_STRING.lower().split(','))

# Настройка секретного ключа для сессий и CSRF защиты
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', secrets.token_hex(32))

# Срок действия временных хранилищ (в днях, по умолчанию 7 дней)
STORAGE_EXPIRATION_DAYS = int(os.getenv('STORAGE_EXPIRATION_DAYS', 7))
app.config['STORAGE_EXPIRATION_DAYS'] = STORAGE_EXPIRATION_DAYS

# Включение/отключение проверки CSRF (для отладки можно отключить)
CSRF_PROTECTION_ENABLED = os.getenv('CSRF_PROTECTION_ENABLED', 'true').lower() == 'true'
app.config['CSRF_PROTECTION_ENABLED'] = CSRF_PROTECTION_ENABLED

# Настройка серверных сессий
app.config['SESSION_TYPE'] = 'filesystem'
app.config['SESSION_FILE_DIR'] = os.path.join(BASE_DIR, 'flask_session')
app.config['SESSION_PERMANENT'] = False
app.config['SESSION_USE_SIGNER'] = True
app.config['SESSION_COOKIE_SECURE'] = os.getenv('SESSION_COOKIE_SECURE', 'true').lower() == 'true'
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(hours=1)

# Защита от брут-форса и rate limiting
# ИСПРАВЛЕНО: Увеличены лимиты для предотвращения ложных блокировок
app.config['MAX_REQUESTS_PER_MINUTE'] = int(os.getenv('MAX_REQUESTS_PER_MINUTE'))  # Было 60, стало 180
app.config['MAX_FAILED_ATTEMPTS'] = int(os.getenv('MAX_FAILED_ATTEMPTS'))  # Было 5, стало 10
app.config['BLOCK_TIME_SECONDS'] = int(os.getenv('BLOCK_TIME_SECONDS'))  # Было 300 (5 минут), стало 180 (3 минуты)

# Отключаем кэширование ответов для предотвращения устаревших данных
app.config['SEND_FILE_MAX_AGE_DEFAULT'] = 0

# Инициализация сессий
Session(app)

# Отключаем ограничение на размер запроса
app.config['MAX_CONTENT_LENGTH'] = None

# Добавляем конфигурацию для загрузки файлов
app.config['UPLOAD_CHUNK_SIZE'] = int(os.getenv('UPLOAD_CHUNK_SIZE', 64)) * 1024  # по умолчанию 64 KB
app.config['MAX_CHUNK_SIZE'] = int(os.getenv('MAX_CHUNK_SIZE', 2)) * 1024 * 1024  # по умолчанию 2 MB

# Константа для количества строк по умолчанию
DEFAULT_LINES_TO_KEEP = int(os.getenv('DEFAULT_LINES_TO_KEEP', 10))

# Хранилище для rate limiting и защиты от брут-форса
request_counters = defaultdict(lambda: {'count': 0, 'reset_time': time.time() + 60})
failed_attempts = defaultdict(lambda: {'count': 0, 'blocked_until': 0})

# Rate limiting и защита от брут-форса
def check_rate_limit(ip_address):
    """Проверяет ограничение частоты запросов для IP-адреса"""
    current_time = time.time()
    counter = request_counters[ip_address]
    
    # Сбрасываем счетчик каждую минуту
    if current_time > counter['reset_time']:
        counter['count'] = 1
        counter['reset_time'] = current_time + 60
        return True
    
    # Увеличиваем счетчик
    counter['count'] += 1
    
    # ИСПРАВЛЕНО: Добавляем исключения для static-файлов и ресурсов, чтобы не блокировать обычных пользователей
    if request.path.startswith('/static/') or request.path.endswith(('.js', '.css', '.ico', '.png', '.jpg', '.jpeg', '.gif')):
        return True
        
    # Проверяем превышение лимита
    if counter['count'] > app.config['MAX_REQUESTS_PER_MINUTE']:
        # ИСПРАВЛЕНО: Добавляем логирование превышения лимита
        logger.warning(f"IP {ip_address} превысил лимит запросов: {counter['count']} запросов за минуту")
        return False
    
    return True

def is_ip_blocked(ip_address):
    """Проверяет, заблокирован ли IP-адрес"""
    current_time = time.time()
    data = failed_attempts[ip_address]
    
    # Если время блокировки прошло, снимаем блокировку
    if data['blocked_until'] > 0 and current_time > data['blocked_until']:
        data['blocked_until'] = 0
        data['count'] = 0
        return False
    
    return data['blocked_until'] > 0

def record_failed_attempt(ip_address):
    """Записывает неудачную попытку для IP-адреса"""
    data = failed_attempts[ip_address]
    data['count'] += 1
    
    # Если превышено максимальное количество попыток, блокируем IP
    if data['count'] >= app.config['MAX_FAILED_ATTEMPTS']:
        data['blocked_until'] = time.time() + app.config['BLOCK_TIME_SECONDS']
        logger.warning(f"IP {ip_address} заблокирован на {app.config['BLOCK_TIME_SECONDS']} секунд после {data['count']} неудачных попыток")

def rate_limit_middleware():
    """Middleware для применения rate limiting к запросам"""
    ip_address = request.remote_addr
    
    # Проверяем блокировку IP
    if is_ip_blocked(ip_address):
        return "Слишком много запросов. Пожалуйста, повторите позже.", 429
    
    # Проверяем rate limit
    if not check_rate_limit(ip_address):
        # Записываем неудачную попытку
        record_failed_attempt(ip_address)
        return "Превышен лимит запросов. Пожалуйста, повторите позже.", 429
    
    return None

@app.before_request
def before_request_middleware():
    """Middleware, выполняемый перед каждым запросом"""
    # Сохраняем время начала запроса для измерения длительности
    request.start_time = time.time()
    
    # ИСПРАВЛЕНО: Пропускаем проверки для статических файлов
    if request.path.startswith('/static/'):
        return None
    
    # Применяем rate limiting
    rate_limit_result = rate_limit_middleware()
    if rate_limit_result:
        return rate_limit_result
    
    # Добавляем случайный идентификатор сессии для предотвращения атак на фиксацию сессии
    if 'session_id' not in session:
        session['session_id'] = secrets.token_hex(16)
    
    # Периодическое обновление CSRF-токена
    if 'csrf_last_updated' not in session or time.time() - session.get('csrf_last_updated', 0) > 3600:
        session['csrf_token'] = secrets.token_hex(16)
        session['csrf_last_updated'] = time.time()

# Добавляем заголовки безопасности для всех ответов
@app.after_request
def add_security_headers(response):
    """Добавляет заголовки безопасности к каждому ответу"""
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'SAMEORIGIN'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    # Обновляем CSP:
    # - Добавляем unpkg.com и cdn.sheetjs.com в script-src
    # - Добавляем blob: в worker-src (для docx-preview и pdf.js)
    # - Добавляем unpkg.com в style-src (на случай, если pptx2html использует CSS оттуда)
    response.headers['Content-Security-Policy'] = (
        "default-src 'self'; "
        "script-src 'self' 'unsafe-inline' https://cdnjs.cloudflare.com https://unpkg.com https://cdn.sheetjs.com; "
        "style-src 'self' 'unsafe-inline' https://cdnjs.cloudflare.com https://cdn.jsdelivr.net https://unpkg.com; "
        "img-src 'self' data:; "
        "font-src 'self' https://cdnjs.cloudflare.com; "
        "worker-src 'self' blob:;"
    )
    response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, max-age=0'
    response.headers['Pragma'] = 'no-cache'
    response.headers['Referrer-Policy'] = 'same-origin'
    response.headers['Permissions-Policy'] = 'geolocation=(), microphone=(), camera=()'

    # Для API-ответов с JSON не нужны некоторые заголовки
    if response.mimetype == 'application/json':
        # Обновляем CSP для JSON, чтобы не переопределять worker-src
        # Оставляем worker-src 'none' т.к. JSON ответы не должны запускать воркеры
        response.headers['Content-Security-Policy'] = "default-src 'none'; worker-src 'none';"

    # Для файлов разного типа нужны разные заголовки
    elif response.mimetype.startswith('image/'):
        response.headers['Content-Disposition'] = 'inline'
    elif response.mimetype in ['application/octet-stream', 'application/zip']:
        # Для загружаемых файлов устанавливаем Content-Disposition: attachment
        if 'Content-Disposition' not in response.headers:
            response.headers['Content-Disposition'] = 'attachment'

    return response

@app.after_request
def log_request(response):
    """Логирует информацию о запросе после его завершения"""
    # Вычисляем время выполнения запроса
    duration = 0
    if hasattr(request, 'start_time'):
        duration = time.time() - request.start_time
    
    # Получаем IP-адрес с учётом возможных прокси
    ip_address = request.headers.get('X-Forwarded-For', request.remote_addr)
    if ip_address and ',' in ip_address:
        # Если передано несколько IP через X-Forwarded-For, берём первый
        ip_address = ip_address.split(',')[0].strip()
    
    # Ограничиваем длину User-Agent для предотвращения атак
    user_agent = request.headers.get('User-Agent', '')[:255]
    
    # Логируем запрос в файл
    log_message = f"{ip_address} - {request.method} {request.path} - {response.status_code} - {duration:.2f}s - {user_agent}"
    if response.status_code >= 400:
        logger.warning(log_message)
    else:
        logger.info(log_message)
        
    # Асинхронно сохраняем информацию о запросе в базу данных
    @run_async
    async def log_to_db():
        try:
            current_time = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            path = request.path[:255]  # Ограничиваем длину пути
            method = request.method[:10]  # Ограничиваем длину метода
            
            async with aiosqlite.connect(DB_PATH) as conn:
                await conn.execute(
                    'INSERT INTO access_log (timestamp, ip_address, user_agent, request_path, request_method, status_code, response_time) VALUES (?, ?, ?, ?, ?, ?, ?)',
                    (current_time, ip_address, user_agent, path, method, response.status_code, duration)
                )
                await conn.commit()
        except Exception as e:
            logger.error(f"Ошибка при логировании запроса в БД: {str(e)}")
    
    # Запускаем асинхронное логирование, только если это не обращение к статическим файлам
    if not request.path.startswith('/static/'):
        try:
            log_to_db()
        except Exception as e:
            logger.error(f"Ошибка при запуске асинхронного логирования: {str(e)}")
    
    return response

# Создаем необходимые директории
os.makedirs(TEMP_STORAGE_DIR, exist_ok=True)
os.makedirs(app.config['SESSION_FILE_DIR'], exist_ok=True)  # Создаем директорию для сессий

# Логирование загруженных конфигураций
logger.info(f"Загружена конфигурация из .env файла:")
logger.info(f"MAX_STORAGE_SIZE_MB: {MAX_STORAGE_SIZE_MB} MB")
logger.info(f"MAX_FILE_SIZE_MB: {MAX_FILE_SIZE_MB} MB")
logger.info(f"MAX_FILES_PER_STORAGE: {MAX_FILES_PER_STORAGE} (0 = не ограничено)")
logger.info(f"ALLOWED_EXTENSIONS: {ALLOWED_EXTENSIONS_STRING}")
logger.info(f"STORAGE_EXPIRATION_DAYS: {STORAGE_EXPIRATION_DAYS}")
logger.info(f"CSRF_PROTECTION_ENABLED: {CSRF_PROTECTION_ENABLED}")

# Инициализация базы данных
async def init_db_async():
    """Асинхронная инициализация базы данных"""
    try:
        async with aiosqlite.connect(DB_PATH) as conn:
            # Включаем защиту от внешних ключей
            await conn.execute("PRAGMA foreign_keys = ON")
            
            # Включаем WAL-режим для улучшения конкурентности и безопасности
            await conn.execute("PRAGMA journal_mode = WAL")
            
            # Создаем таблицу настроек пользователя, если её нет
            await conn.execute('''CREATE TABLE IF NOT EXISTS user_settings
                         (user_id INTEGER PRIMARY KEY,
                          lines_to_keep INTEGER DEFAULT 10,
                          theme TEXT DEFAULT 'dark')''')
            
            # Проверяем, есть ли колонка theme
            cursor = await conn.execute("PRAGMA table_info(user_settings)")
            columns_raw = await cursor.fetchall()
            columns = [column[1] for column in columns_raw]
            
            # Если колонки theme нет, добавляем её
            if 'theme' not in columns:
                await conn.execute('ALTER TABLE user_settings ADD COLUMN theme TEXT DEFAULT "dark"')
            
            # Проверяем, есть ли таблица temp_links
            cursor = await conn.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='temp_links'")
            table_exists = await cursor.fetchone()
            
            # Если таблица не существует, создаем её
            if not table_exists:
                await conn.execute('''
                    CREATE TABLE IF NOT EXISTS temp_links (
                        link_id TEXT PRIMARY KEY,
                        expires_at TEXT NOT NULL,
                        user_id INTEGER,
                        created_at TEXT,
                        extension_count INTEGER DEFAULT 0
                    )
                ''')
                logger.info("Создана таблица temp_links")
            
            # Если таблица существует, проверяем наличие нужных колонок
            else:
                cursor = await conn.execute("PRAGMA table_info(temp_links)")
                columns_raw = await cursor.fetchall()
                columns = [column[1] for column in columns_raw]
                
                # Если колонки created_at нет, добавляем её
                if 'created_at' not in columns:
                    try:
                        # Добавляем колонку created_at
                        await conn.execute('ALTER TABLE temp_links ADD COLUMN created_at TEXT')
                        
                        # Обновляем значения created_at на основе expires_at
                        # Предполагаем, что хранилище было создано за 7 дней до истечения срока
                        cursor = await conn.execute('SELECT link_id, expires_at FROM temp_links')
                        links = await cursor.fetchall()
                        
                        for link in links:
                            link_id, expires_at = link
                            if expires_at:
                                # Очищаем от микросекунд
                                if '.' in expires_at:
                                    expires_at = expires_at.split('.')[0]
                                    
                                try:
                                    # Преобразуем в datetime и вычитаем 7 дней
                                    expires_datetime = datetime.strptime(expires_at, '%Y-%m-%d %H:%M:%S')
                                    created_datetime = expires_datetime - timedelta(days=7)
                                    created_at = created_datetime.strftime('%Y-%m-%d %H:%M:%S')
                                    
                                    # Обновляем запись с использованием параметризованного запроса
                                    await conn.execute('UPDATE temp_links SET created_at = ? WHERE link_id = ?', 
                                                    (created_at, link_id))
                                except Exception as e:
                                    logger.error(f"Ошибка при обновлении created_at для {link_id}: {str(e)}")
                        
                        logger.info("Добавлена колонка created_at в таблицу temp_links")
                    except Exception as e:
                        logger.error(f"Ошибка при добавлении колонки created_at: {str(e)}")
                
                # Если колонки extension_count нет, добавляем её
                if 'extension_count' not in columns:
                    try:
                        # Добавляем колонку extension_count
                        await conn.execute('ALTER TABLE temp_links ADD COLUMN extension_count INTEGER DEFAULT 0')
                        logger.info("Добавлена колонка extension_count в таблицу temp_links")
                    except Exception as e:
                        logger.error(f"Ошибка при добавлении колонки extension_count: {str(e)}")
            
            # Добавляем индекс для ускорения поиска по expires_at
            try:
                await conn.execute('CREATE INDEX IF NOT EXISTS idx_temp_links_expires_at ON temp_links(expires_at)')
                logger.info("Создан индекс на колонку expires_at")
            except Exception as e:
                logger.error(f"Ошибка при создании индекса: {str(e)}")
                
            # Создаем таблицу для логирования доступа, если её нет
            try:
                await conn.execute('''
                    CREATE TABLE IF NOT EXISTS access_log (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        timestamp TEXT NOT NULL,
                        ip_address TEXT,
                        user_agent TEXT,
                        request_path TEXT,
                        request_method TEXT,
                        status_code INTEGER,
                        response_time REAL
                    )
                ''')
                logger.info("Создана таблица access_log")
            except Exception as e:
                logger.error(f"Ошибка при создании таблицы access_log: {str(e)}")
                
            await conn.commit()
    except Exception as e:
        logger.error(f"Ошибка при инициализации базы данных: {str(e)}")
        raise

# Синхронная обертка для инициализации базы данных
def init_db():
    """Инициализация базы данных"""
    return run_async(init_db_async)()

# Инициализируем базу данных при запуске
init_db()

# Асинхронная функция для получения user_id по link_id
async def get_user_id_by_link_id_async(link_id):
    """Асинхронное получение user_id по link_id"""
    try:
        async with aiosqlite.connect(DB_PATH) as conn:
            cursor = await conn.execute('SELECT user_id FROM temp_links WHERE link_id = ?', (link_id,))
            result = await cursor.fetchone()
            return result[0] if result else None
    except Exception as e:
        logger.error(f"Ошибка при получении user_id для link_id {link_id}: {str(e)}")
        return None

# Синхронная обертка
def get_user_id_by_link_id(link_id):
    """Получение user_id по link_id (синхронная обертка)"""
    return run_async(get_user_id_by_link_id_async)(link_id)

def get_temp_storage_path(link_id):
    """Получение пути к временному хранилищу"""
    return os.path.join(TEMP_STORAGE_DIR, link_id)

def get_temp_storage_size(link_id):
    """Получение размера временного хранилища"""
    storage_path = get_temp_storage_path(link_id)
    if not os.path.exists(storage_path):
        return 0
    total_size = 0
    for dirpath, _, filenames in os.walk(storage_path):
        for f in filenames:
            fp = os.path.join(dirpath, f)
            total_size += os.path.getsize(fp)
    return max(0, total_size)  # Гарантируем положительное значение

def check_temp_storage_limit(link_id):
    """Проверка лимита временного хранилища (500 MB)"""
    return get_temp_storage_size(link_id) < 500 * 1024 * 1024

async def is_temp_storage_valid_async(link_id):
    """Асинхронная проверка валидности временного хранилища"""
    try:
        # Получаем текущее московское время
        from datetime import datetime
        moscow_tz = pytz.timezone('Europe/Moscow')
        now = datetime.now(moscow_tz)
        current_time_iso = now.strftime('%Y-%m-%d %H:%M:%S')
        
        async with aiosqlite.connect(DB_PATH) as conn:
            # Сначала проверяем существование хранилища
            cursor = await conn.execute('SELECT expires_at FROM temp_links WHERE link_id = ?', (link_id,))
            result = await cursor.fetchone()
            
            if not result:
                logger.info(f"Хранилище {link_id} не найдено")
                return False
                
            # Получаем дату истечения и убираем микросекунды, если они есть
            expires_at = result[0]
            if '.' in expires_at:
                expires_at = expires_at.split('.')[0]
                
            # Обновляем срок действия хранилища, если изменилась настройка STORAGE_EXPIRATION_DAYS
            if app.config['STORAGE_EXPIRATION_DAYS'] != 7:  # Если отличается от дефолтной
                try:
                    # Проверяем наличие поля created_at в таблице temp_links
                    cursor = await conn.execute("PRAGMA table_info(temp_links)")
                    columns = await cursor.fetchall()
                    column_names = [column[1] for column in columns]
                    
                    has_created_at = 'created_at' in column_names
                    
                    if has_created_at:
                        # Получаем время создания хранилища
                        cursor = await conn.execute('SELECT created_at FROM temp_links WHERE link_id = ?', (link_id,))
                        created_result = await cursor.fetchone()
                        
                        if created_result and created_result[0]:
                            created_at = created_result[0]
                            # Если есть поле created_at, вычисляем новое expires_at
                            if '.' in created_at:
                                created_at = created_at.split('.')[0]
                                
                            # Преобразуем строку в объект datetime
                            created_datetime = datetime.strptime(created_at, '%Y-%m-%d %H:%M:%S')
                            created_datetime = moscow_tz.localize(created_datetime)
                            
                            # Вычисляем новую дату истечения
                            new_expires_datetime = created_datetime + timedelta(days=app.config['STORAGE_EXPIRATION_DAYS'])
                            new_expires_at = new_expires_datetime.strftime('%Y-%m-%d %H:%M:%S')
                            
                            # Проверяем, отличается ли новая дата истечения от текущей
                            if new_expires_at != expires_at:
                                logger.info(f"Обновляем срок действия хранилища {link_id} с {expires_at} на {new_expires_at}")
                                await conn.execute('UPDATE temp_links SET expires_at = ? WHERE link_id = ?', 
                                                (new_expires_at, link_id))
                                await conn.commit()
                                expires_at = new_expires_at
                    else:
                        logger.warning(f"Поле created_at не найдено в таблице temp_links. Срок действия хранилища {link_id} не обновлен.")
                except Exception as e:
                    logger.error(f"Ошибка при обновлении срока действия хранилища {link_id}: {str(e)}")
                    
            # Сравниваем даты в строковом формате
            is_valid = expires_at > current_time_iso
            
            if not is_valid:
                logger.info(f"Хранилище {link_id} истекло ({expires_at} <= {current_time_iso})")
            else:
                logger.info(f"Хранилище {link_id} действительно ({expires_at} > {current_time_iso})")
                
            return is_valid
                
    except Exception as e:
        logger.error(f"Ошибка при проверке срока действия хранилища {link_id}: {str(e)}")
        return False

def is_temp_storage_valid(link_id):
    """Проверка валидности временного хранилища (синхронная обертка)"""
    return run_async(is_temp_storage_valid_async)(link_id)

async def get_user_theme_async(user_id):
    """Асинхронное получение темы пользователя"""
    try:
        async with aiosqlite.connect(DB_PATH) as conn:
            cursor = await conn.execute('SELECT theme FROM user_settings WHERE user_id = ?', (user_id,))
            result = await cursor.fetchone()
            return result[0] if result and result[0] else 'dark'
    except Exception as e:
        logger.error(f"Ошибка при получении темы пользователя: {str(e)}")
        return 'dark'

def get_user_theme(user_id):
    """Получение темы пользователя (синхронная обертка)"""
    return run_async(get_user_theme_async)(user_id)

async def set_user_theme_async(user_id, theme):
    """Асинхронная установка темы пользователя"""
    try:
        async with aiosqlite.connect(DB_PATH) as conn:
            await conn.execute('''INSERT OR REPLACE INTO user_settings 
                         (user_id, theme, lines_to_keep) 
                         VALUES (?, ?, 
                                COALESCE((SELECT lines_to_keep FROM user_settings WHERE user_id = ?), 
                                ?))''', 
                     (user_id, theme, user_id, DEFAULT_LINES_TO_KEEP))
            await conn.commit()
            logger.info(f"Тема '{theme}' успешно установлена для пользователя {user_id}")  # Добавлено логирование успеха
            return True
    except Exception as e:
        # Логируем конкретную ошибку базы данных
        logger.error(f"Ошибка базы данных при установке темы для пользователя {user_id}: {str(e)}", exc_info=True)
        return False

def set_user_theme(user_id, theme):
    """Установка темы пользователя (синхронная обертка)"""
    return run_async(set_user_theme_async)(user_id, theme)

# Функция для проверки валидности расширения файла
def allowed_file(filename):
    """Проверяет, что загружаемый файл имеет разрешенное расширение из белого списка"""
    # Проверяем на валидность имени файла
    if not filename or '.' not in filename:
        return False
        
    # Нормализуем имя файла
    filename = filename.lower()
    
    # Проверяем на потенциально опасные последовательности символов в имени
    dangerous_patterns = [
        '../', './', '/..',  # Path traversal
        '\\', '%00',         # Null byte injection
        '<?', '<?php',       # PHP tags
        '<script', 'javascript:', 'vbscript:',  # XSS
        'cmd.exe', 'powershell', 'bash'  # Command execution
    ]
    
    for pattern in dangerous_patterns:
        if pattern in filename:
            return False
    
    # Дополнительная проверка на очень длинные имена файлов
    if len(filename) > 255:
        return False
    
    # Получаем все расширения файла (защита от двойных расширений)
    extensions = filename.split('.')
    
    # Проверяем основное расширение
    extension = extensions[-1]
    
    # Проверяем по белому списку (если он есть)
    if not app.config['ALLOWED_EXTENSIONS']:
        # Если белый список пуст - все файлы запрещены
        return False
        
    # Разрешены только файлы с расширениями из белого списка
    return extension in app.config['ALLOWED_EXTENSIONS']

# CSRF защита
def generate_csrf_token():
    """Генерирует CSRF токен для защиты форм"""
    # Если токен уже существует и не нуждается в обновлении, используем его
    if 'csrf_token' in session and 'csrf_last_updated' in session:
        last_updated = session.get('csrf_last_updated', 0)
        # Обновляем токен каждый час
        if time.time() - last_updated < 3600:
            return session['csrf_token']
    
    # Генерируем новый токен с использованием криптостойкого генератора случайных чисел
    token = secrets.token_hex(32)
    session['csrf_token'] = token
    session['csrf_last_updated'] = time.time()
    return token

def check_csrf_token():
    """Проверяет CSRF токен в запросе"""
    # Пробуем получить токен из разных источников
    token = None
    
    # Из заголовка X-CSRF-Token
    header_token = request.headers.get('X-CSRF-Token')
    if header_token:
        token = header_token
    
    # Из формы (form data)
    form_token = request.form.get('csrf_token')
    if not token and form_token:
        token = form_token
    
    # Из JSON-данных
    if not token and request.is_json:
        json_data = request.get_json(silent=True)
        if json_data and isinstance(json_data, dict):
            json_token = json_data.get('csrf_token')
            if json_token:
                token = json_token
    
    # Проверяем токен
    if not token or not session.get('csrf_token') or not secrets.compare_digest(token, session.get('csrf_token')):
        # Записываем попытку CSRF-атаки
        ip = request.remote_addr
        logger.warning(f"CSRF-атака предотвращена с IP {ip}")
        record_failed_attempt(ip)  # Записываем неудачную попытку для IP
        return False
    
    return True

# Защита маршрутов от CSRF атак
def csrf_protected(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        # Если CSRF защита отключена, просто выполняем функцию
        if not app.config['CSRF_PROTECTION_ENABLED']:
            return f(*args, **kwargs)
            
        if request.method in ['POST', 'PUT', 'DELETE', 'PATCH']:
            if not check_csrf_token():
                logger.warning("CSRF-атака предотвращена")
                return jsonify({'error': 'Недействительный CSRF токен. Пожалуйста, обновите страницу и повторите попытку.'}), 403
        return f(*args, **kwargs)
    return decorated_function

# Внедряем CSRF токен в шаблоны
@app.context_processor
def inject_csrf_token():
    return dict(csrf_token=generate_csrf_token())

# Добавляем кастомные фильтры в Jinja2
@app.template_filter('escapejs')
def escapejs_filter(value):
    """Экранирует строку для использования в JavaScript"""
    replacements = {
        '\\': '\\\\',
        '\n': '\\n',
        '\r': '\\r',
        '\t': '\\t',
        '\f': '\\f',
        '\b': '\\b',
        '"': '\\"',
        "'": "\\'"
    }
    result = str(value)
    for char, replacement in replacements.items():
        result = result.replace(char, replacement)
    return result

# Функция для форматирования размера файла
def format_file_size(size_bytes):
    """Форматирует размер файла в человекочитаемый вид"""
    if size_bytes == 0:
        return "0 B"
    size_name = ("B", "KB", "MB", "GB", "TB", "PB", "EB", "ZB", "YB")
    i = int(math.floor(math.log(size_bytes, 1024)))
    p = math.pow(1024, i)
    s = round(size_bytes / p, 2)
    return f"{s} {size_name[i]}"

# Функция для получения класса иконки Font Awesome по расширению
def get_icon_class(extension):
    """Возвращает класс иконки Font Awesome для данного расширения файла."""
    ext_lower = extension.lower()
    icon_map = {
        # Изображения
        'jpg': 'fas fa-file-image', 'jpeg': 'fas fa-file-image', 'png': 'fas fa-file-image',
        'gif': 'fas fa-file-image', 'bmp': 'fas fa-file-image', 'svg': 'fas fa-file-image',
        'webp': 'fas fa-file-image', 'ico': 'fas fa-file-image', 'tiff': 'fas fa-file-image',
        'tif': 'fas fa-file-image',
        # Документы
        'pdf': 'fas fa-file-pdf',
        'doc': 'fas fa-file-word', 'docx': 'fas fa-file-word',
        'xls': 'fas fa-file-excel', 'xlsx': 'fas fa-file-excel',
        'ppt': 'fas fa-file-powerpoint', 'pptx': 'fas fa-file-powerpoint',
        'txt': 'fas fa-file-alt', 'rtf': 'fas fa-file-alt',
        'odt': 'fas fa-file-alt', 'ods': 'fas fa-file-alt', 'odp': 'fas fa-file-alt',
        # Архивы
        'zip': 'fas fa-file-archive', 'rar': 'fas fa-file-archive', '7z': 'fas fa-file-archive',
        'tar': 'fas fa-file-archive', 'gz': 'fas fa-file-archive', 'bz2': 'fas fa-file-archive',
        # Аудио
        'mp3': 'fas fa-file-audio', 'wav': 'fas fa-file-audio', 'ogg': 'fas fa-file-audio',
        'flac': 'fas fa-file-audio', 'aac': 'fas fa-file-audio',
        # Видео
        'mp4': 'fas fa-file-video', 'avi': 'fas fa-file-video', 'mkv': 'fas fa-file-video',
        'mov': 'fas fa-file-video', 'wmv': 'fas fa-file-video',
        # Код
        'html': 'fas fa-file-code', 'htm': 'fas fa-file-code', 'css': 'fas fa-file-code',
        'js': 'fas fa-file-code', 'json': 'fas fa-file-code', 'xml': 'fas fa-file-code',
        'py': 'fas fa-file-code', 'java': 'fas fa-file-code', 'c': 'fas fa-file-code',
        'cpp': 'fas fa-file-code', 'h': 'fas fa-file-code', 'hpp': 'fas fa-file-code',
        'cs': 'fas fa-file-code', 'php': 'fas fa-file-code', 'rb': 'fas fa-file-code',
        'go': 'fas fa-file-code', 'rs': 'fas fa-file-code', 'ts': 'fas fa-file-code',
        'sql': 'fas fa-database', 'sh': 'fas fa-terminal', 'bat': 'fas fa-terminal',
        # Другие
        'csv': 'fas fa-file-csv', 'md': 'fab fa-markdown',
    }
    return icon_map.get(ext_lower, 'fas fa-file') # Иконка по умолчанию

# Добавляем функции в контекст Jinja
app.jinja_env.globals.update(get_icon_class=get_icon_class)
app.jinja_env.globals.update(format_file_size=format_file_size)

# --- Добавленные функции для очистки ---

async def cleanup_expired_storages_async():
    """Асинхронная очистка истекших временных хранилищ"""
    try:
        moscow_tz = pytz.timezone('Europe/Moscow')
        now = datetime.now(moscow_tz)
        current_time_iso = now.strftime('%Y-%m-%d %H:%M:%S')
        
        async with aiosqlite.connect(DB_PATH) as conn:
            # Находим все истекшие хранилища
            cursor = await conn.execute('SELECT link_id FROM temp_links WHERE expires_at <= ?', (current_time_iso,))
            expired_links = await cursor.fetchall()
            
            if not expired_links:
                logger.info("Нет истекших хранилищ для очистки.")
                return

            logger.info(f"Найдено {len(expired_links)} истекших хранилищ для удаления.")
            
            deleted_count = 0
            for link_tuple in expired_links:
                link_id = link_tuple[0]
                storage_path = get_temp_storage_path(link_id)
                
                # Удаляем директорию хранилища
                if os.path.exists(storage_path):
                    try:
                        shutil.rmtree(storage_path)
                        logger.info(f"Удалена директория истекшего хранилища: {link_id}")
                    except Exception as e:
                        logger.error(f"Ошибка при удалении директории хранилища {link_id}: {str(e)}")
                
                # Удаляем запись из базы данных
                try:
                    await conn.execute('DELETE FROM temp_links WHERE link_id = ?', (link_id,))
                    deleted_count += 1
                except Exception as e:
                    logger.error(f"Ошибка при удалении записи о хранилище {link_id} из БД: {str(e)}")

            await conn.commit()
            logger.info(f"Успешно удалено {deleted_count} записей об истекших хранилищах из БД.")
            
    except Exception as e:
        logger.error(f"Ошибка во время очистки истекших хранилищ: {str(e)}")

def cleanup_expired_sessions():
    """Очистка старых файлов сессий"""
    try:
        session_dir = app.config['SESSION_FILE_DIR']
        if not os.path.exists(session_dir):
            logger.warning(f"Директория сессий не найдена: {session_dir}")
            return

        now = time.time()
        lifetime_seconds = app.config['PERMANENT_SESSION_LIFETIME'].total_seconds()
        deleted_count = 0

        for filename in os.listdir(session_dir):
            file_path = os.path.join(session_dir, filename)
            try:
                # Проверяем, что это файл
                if os.path.isfile(file_path):
                    # Получаем время последнего доступа к файлу
                    last_accessed = os.path.getatime(file_path)
                    # Если файл не использовался дольше времени жизни сессии, удаляем его
                    if now - last_accessed > lifetime_seconds:
                        os.remove(file_path)
                        deleted_count += 1
                        logger.debug(f"Удален старый файл сессии: {filename}")
            except Exception as e:
                logger.error(f"Ошибка при обработке файла сессии {filename}: {str(e)}")
        
        if deleted_count > 0:
            logger.info(f"Удалено {deleted_count} старых файлов сессий.")
        else:
            logger.info("Нет старых файлов сессий для удаления.")
            
    except Exception as e:
        logger.error(f"Ошибка во время очистки файлов сессий: {str(e)}")

def periodic_cleanup():
    """Периодическая задача для очистки истекших данных"""
    cleanup_interval_hours = int(os.getenv('CLEANUP_INTERVAL_HOURS', 1)) # По умолчанию каждый час
    cleanup_interval_seconds = cleanup_interval_hours * 3600
    
    logger.info(f"Запуск периодической очистки каждые {cleanup_interval_hours} час(а).")
    
    while True:
        try:
            logger.info("Начало периодической очистки...")
            
            # Очистка истекших хранилищ (асинхронно)
            run_async(cleanup_expired_storages_async)()
            
            # Очистка старых сессий (синхронно)
            cleanup_expired_sessions()
            
            logger.info("Периодическая очистка завершена.")
        except Exception as e:
            logger.error(f"Ошибка в потоке периодической очистки: {str(e)}")
        
        # Ждем до следующего запуска
        time.sleep(cleanup_interval_seconds)

# --- Конец добавленных функций ---

# Уникальные идентификаторы сессий загрузки для обработки конкурентной загрузки
upload_sessions = {}

# Безопасная обработка ошибок 
def handle_error(e, default_message="Внутренняя ошибка сервера", log_message=None):
    """Централизованная обработка ошибок с логированием и без утечки системной информации"""
    if log_message:
        logger.error(log_message)
    logger.exception(f"Ошибка: {str(e)}") # Используем logger.exception для traceback
    
    # Не показываем чувствительную информацию в ответе клиенту
    return default_message

# Добавляем маршрут для favicon
@app.route('/favicon.ico')
def favicon():
    """Отправка favicon"""
    return send_from_directory(os.path.join(app.root_path, 'web', 'static', 'web', 'image'),
                               'favicon.ico', mimetype='image/vnd.microsoft.icon')

@app.route('/')
def index():
    """Главная страница"""
    return render_template('index.html')

@app.route('/<link_id>')
def temp_storage(link_id):
    """Страница временного хранилища"""
    try:
        # Проверка на безопасность link_id (только буквенно-цифровые символы)
        if not re.match(r'^[a-zA-Z0-9_-]+$', link_id):
            logger.warning(f"Попытка доступа с некорректным link_id: {link_id}")
            return "Временное хранилище не найдено", 404
            
        # Проверяем валидность хранилища
        try:
            is_valid = is_temp_storage_valid(link_id)
        except Exception as e:
            logger.error(f"Ошибка при проверке валидности хранилища {link_id}: {str(e)}")
            return render_template('error.html', 
                                 message="Произошла ошибка при проверке хранилища. Пожалуйста, попробуйте позже."), 500
        
        if not is_valid:
            storage_path = get_temp_storage_path(link_id)
            if os.path.exists(storage_path):
                try:
                    shutil.rmtree(storage_path)
                    logger.info(f"Удалена директория недействительного хранилища: {link_id}")
                except Exception as e:
                    logger.error(f"Ошибка при удалении директории недействительного хранилища {link_id}: {str(e)}")
            
            # Используем асинхронную функцию через декоратор
            @run_async
            async def delete_expired_storage():
                try:
                    async with aiosqlite.connect(DB_PATH) as conn:
                        await conn.execute('DELETE FROM temp_links WHERE link_id = ?', (link_id,))
                        await conn.commit()
                        logger.info(f"Удалена запись о недействительном хранилище: {link_id}")
                except Exception as e:
                    logger.error(f"Ошибка при удалении записи о хранилище {link_id}: {str(e)}")
            
            try:
                delete_expired_storage()
            except Exception as e:
                logger.error(f"Ошибка при удалении записи о хранилище {link_id}: {str(e)}")
                
            return "Временное хранилище не найдено или срок его действия истек", 404

        # Получаем user_id из базы асинхронно
        try:
            @run_async
            async def get_user_id_and_expires_at():
                async with aiosqlite.connect(DB_PATH) as conn:
                    cursor = await conn.execute('SELECT user_id, expires_at FROM temp_links WHERE link_id = ?', (link_id,))
                    result = await cursor.fetchone()
                    return result if result else (None, None)
            
            user_data = get_user_id_and_expires_at()
            user_id, expires_at = user_data if user_data else (None, None)
            theme = get_user_theme(user_id) if user_id else 'dark'
        except Exception as e:
            logger.error(f"Ошибка при получении данных пользователя для хранилища {link_id}: {str(e)}")
            user_id, expires_at = None, None
            theme = 'dark'
        
        # Рассчитываем оставшееся время до истечения срока хранилища
        remaining_time = None
        if expires_at:
            try:
                # Форматируем дату истечения без микросекунд
                if '.' in expires_at:
                    expires_at = expires_at.split('.')[0]
                
                # Получаем текущее московское время
                moscow_tz = pytz.timezone('Europe/Moscow')
                now = datetime.now(moscow_tz)
                expires_datetime = datetime.strptime(expires_at, '%Y-%m-%d %H:%M:%S')
                expires_datetime = moscow_tz.localize(expires_datetime)
                
                # Рассчитываем оставшееся время
                time_delta = expires_datetime - now
                days = time_delta.days
                hours, remainder = divmod(time_delta.seconds, 3600)
                minutes, _ = divmod(remainder, 60)
                
                if days >= 0:
                    remaining_time = f"{days} дн., {hours} ч., {minutes} мин."
            except Exception as e:
                logger.error(f"Ошибка при расчете оставшегося времени: {str(e)}")
        
        # Получаем список файлов
        storage_path = get_temp_storage_path(link_id)
        if not os.path.exists(storage_path):
            os.makedirs(storage_path)
        
        files = []
        total_size = 0
        
        try:
            for filename in os.listdir(storage_path):
                file_path = os.path.join(storage_path, filename)
                if os.path.isfile(file_path):
                    try:
                        file_size = max(0, os.path.getsize(file_path))
                        total_size += file_size
                        
                        # Экранируем имя файла для предотвращения XSS
                        safe_filename = html.escape(filename)
                        
                        files.append({
                            'name': safe_filename,
                            'raw_name': filename,  # Оригинальное имя для операций с файлами
                            'size': file_size,
                            'modified': datetime.fromtimestamp(os.path.getmtime(file_path))
                        })
                    except (OSError, IOError) as e:
                        logger.error(f"Ошибка при получении информации о файле {filename}: {str(e)}")
        except Exception as e:
            logger.error(f"Ошибка при чтении содержимого директории {storage_path}: {str(e)}")
        
        files.sort(key=lambda x: x['modified'], reverse=True)
        
        # Обеспечиваем безопасные значения
        total_size = max(0, total_size)
        used_space = total_size / (1024 * 1024)  # переводим в MB
        used_percent = min(100, max(0, (total_size / app.config['MAX_STORAGE_SIZE']) * 100))
        
        # Рендерим шаблон с данными о хранилище
        try:
            return render_template('temp_storage.html',
                                link_id=link_id,
                                files=files,
                                used_space=used_space,
                                used_percent=used_percent,
                                theme=theme,
                                expires_at=expires_at,
                                # Передаем список расширений как есть
                                allowed_extensions=app.config['ALLOWED_EXTENSIONS'])
        except Exception as e:
            logger.error(f"Ошибка при рендеринге шаблона: {str(e)}")
            return "Произошла ошибка при загрузке страницы. Пожалуйста, попробуйте позже.", 500
        
    except Exception as e:
        logger.error(f"Ошибка при загрузке страницы: {str(e)}")
        return "Произошла ошибка при загрузке страницы. Пожалуйста, попробуйте позже.", 500

@app.route('/<link_id>/download/<path:filename>')  # Изменяем <filename> на <path:filename> для обработки слешей
def download_file(link_id, filename):
    """Скачивание файла из временного хранилища"""
    try:
        # Проверка на безопасность link_id (только буквенно-цифровые символы)
        if not re.match(r'^[a-zA-Z0-9_-]+$', link_id):
            logger.warning(f"Попытка скачивания с некорректным link_id: {link_id}")
            return jsonify({'error': 'Недействительный идентификатор хранилища'}), 400
            
        # Проверяем валидность хранилища
        if not is_temp_storage_valid(link_id):
            logger.warning(f"Попытка скачивания из недействительного хранилища: {link_id}")
            return jsonify({'error': 'Хранилище недействительно или срок его действия истек'}), 404
        
        # Декодируем имя файла из URL
        decoded_filename = unquote(filename)
        logger.debug(f"Запрошен файл (декодированный): {decoded_filename}")

        # Базовая проверка безопасности декодированного имени файла
        if '..' in decoded_filename or decoded_filename.startswith('/'):
            logger.warning(f"Обнаружена попытка path traversal: {decoded_filename}")
            return "Недопустимое имя файла", 400

        # Проверка на длину имени файла
        if len(decoded_filename) > 255:
            logger.warning(f"Слишком длинное имя файла при скачивании: {len(decoded_filename)}")
            return "Слишком длинное имя файла", 400
            
        storage_path = get_temp_storage_path(link_id)
        # Используем декодированное имя для пути к файлу
        file_path = os.path.join(storage_path, decoded_filename)
        logger.debug(f"Полный путь к файлу: {file_path}")
        
        # Проверка безопасности пути
        real_file_path = os.path.abspath(file_path)
        real_storage_path = os.path.abspath(storage_path)
        if not real_file_path.startswith(real_storage_path):
            logger.error(f"Попытка доступа к файлу вне хранилища: {file_path}")
            return "Доступ запрещен", 403
            
        # Проверка существования файла
        if not os.path.exists(file_path):
            logger.warning(f"Файл не найден: {file_path}")
            # Дополнительное логирование: список файлов в директории
            try:
                files_in_dir = os.listdir(storage_path)
                logger.debug(f"Файлы в директории {storage_path}: {files_in_dir}")
            except Exception as list_err:
                logger.error(f"Не удалось получить список файлов в {storage_path}: {list_err}")
            return "Файл не найден", 404
            
        # Проверка что это регулярный файл, а не директория или символическая ссылка
        if not os.path.isfile(file_path):
            logger.error(f"Попытка скачать не файл: {file_path}")
            return "Недопустимый тип объекта", 400
            
        # Проверка размера файла
        try:
            file_size = os.path.getsize(file_path)
            if file_size > app.config['MAX_FILE_SIZE']:
                logger.error(f"Попытка скачать слишком большой файл: {file_path} ({file_size} байт)")
                return "Файл слишком большой", 413
        except Exception as e:
            logger.error(f"Ошибка при проверке размера файла {filename}: {str(e)}")
            
        # Устанавливаем правильные MIME-типы для безопасности
        mime_type = 'application/octet-stream'
        extensions_mime = {
            'pdf': 'application/pdf',
            'txt': 'text/plain',
            'png': 'image/png',
            'jpg': 'image/jpeg',
            'jpeg': 'image/jpeg',
            'gif': 'image/gif',
            'svg': 'image/svg+xml',
            'webp': 'image/webp',
            'bmp': 'image/bmp',
            'ico': 'image/x-icon',
            'tiff': 'image/tiff',
            'tif': 'image/tiff',
            'zip': 'application/zip',
            'doc': 'application/msword',
            'docx': 'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
            'xls': 'application/vnd.ms-excel',
            'xlsx': 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
            'ppt': 'application/vnd.ms-powerpoint',
            'pptx': 'application/vnd.openxmlformats-officedocument.presentationml.presentation',
            'odt': 'application/vnd.oasis.opendocument.text',
            'ods': 'application/vnd.oasis.opendocument.spreadsheet',
            'odp': 'application/vnd.oasis.opendocument.presentation',
            'rtf': 'application/rtf',
            'csv': 'text/csv',
            'html': 'text/html',
            'htm': 'text/html',
            'json': 'application/json',
            'xml': 'application/xml',
            'js': 'application/javascript',
            'css': 'text/css',
        }
        
        # Получаем расширение файла из декодированного имени
        ext = ''
        if '.' in decoded_filename:
            ext = decoded_filename.rsplit('.', 1)[1].lower()
            mime_type = extensions_mime.get(ext, 'application/octet-stream')
            
        try:
            # Проверяем, является ли запрос запросом на скачивание или просмотр
            is_download_request = request.args.get('download', 'false').lower() == 'true'

            logger.info(f"Отправка файла: {decoded_filename}, MIME: {mime_type}, as_attachment: {is_download_request}")

            # Используем is_download_request для определения, скачивать файл или показывать inline
            # Используем decoded_filename для download_name
            return send_file(
                file_path,
                mimetype=mime_type,
                as_attachment=is_download_request,  # True если download=true, иначе False (inline)
                download_name=decoded_filename if is_download_request else None  # Имя файла только при скачивании
            )
        except Exception as e:
            logger.error(f"Ошибка при отправке файла {decoded_filename}: {str(e)}")
            return "Ошибка при отправке файла", 500
            
    except Exception as e:
        logger.error(f"Ошибка при скачивании файла: {str(e)}")
        return "Произошла ошибка при скачивании файла", 500

@app.route('/health')
def health_check():
    """Проверка работоспособности сервера"""
    return "OK", 200

@app.route('/<link_id>/upload', methods=['POST'])
@csrf_protected
def upload_file(link_id):
    """Загрузка файла во временное хранилище (поддержка чанков)"""
    try:
        # Проверка на безопасность link_id
        if not re.match(r'^[a-zA-Z0-9_-]+$', link_id):
            logger.warning(f"Попытка загрузки с некорректным link_id: {link_id}")
            return jsonify({'error': 'Недействительный идентификатор хранилища'}), 400

        # Проверяем валидность хранилища ПЕРЕД загрузкой
        if not is_temp_storage_valid(link_id):
            logger.warning(f"Попытка загрузки в недействительное хранилище: {link_id}")
            return jsonify({'error': 'Хранилище недействительно или срок его действия истек'}), 404

        # Проверка лимита хранилища
        storage_path = get_temp_storage_path(link_id)
        os.makedirs(storage_path, exist_ok=True)
        current_size = get_temp_storage_size(link_id)

        # Получаем данные из формы
        file = request.files.get('file')
        chunk_number = request.form.get('chunk', type=int)
        total_chunks = request.form.get('chunks', type=int)
        total_size = request.form.get('total_size', type=int)
        upload_session_id = request.form.get('upload_session_id')

        # Проверяем наличие необходимых данных
        if not file or chunk_number is None or total_chunks is None or total_size is None or not upload_session_id:
            logger.warning(f"Неполные данные при загрузке в {link_id}")
            return jsonify({'error': 'Неполные данные запроса'}), 400

        # Сохраняем оригинальное имя файла
        original_filename = file.filename
        # Базовая проверка безопасности оригинального имени файла
        # Запрещаем символы, которые могут использоваться для path traversal
        if not original_filename or '..' in original_filename or '/' in original_filename or '\\' in original_filename:
             logger.warning(f"Небезопасное оригинальное имя файла при загрузке в {link_id}: {original_filename}")
             return jsonify({'error': 'Недопустимое имя файла'}), 400

        # Проверка длины оригинального имени файла
        if len(original_filename) > 255:
            logger.warning(f"Слишком длинное оригинальное имя файла при загрузке в {link_id}: {len(original_filename)}")
            return jsonify({'error': 'Слишком длинное имя файла'}), 400

        # Проверка разрешенного типа файла (используем оригинальное имя)
        if not allowed_file(original_filename):
            logger.warning(f"Попытка загрузки файла запрещенного типа в {link_id}: {original_filename}")
            allowed_ext_str = ', '.join(app.config['ALLOWED_EXTENSIONS'])
            return jsonify({'error': f'Тип файла не разрешен. Разрешены только: {allowed_ext_str}'}), 400

        # Проверка лимита количества файлов
        if app.config['MAX_FILES_PER_STORAGE'] > 0:
            try:
                current_files_count = len([name for name in os.listdir(storage_path) if os.path.isfile(os.path.join(storage_path, name))])
                # Если это первый чанк нового файла, проверяем лимит
                if chunk_number == 0 and current_files_count >= app.config['MAX_FILES_PER_STORAGE']:
                    logger.warning(f"Превышен лимит количества файлов в хранилище {link_id}")
                    return jsonify({'error': f'Превышен лимит количества файлов ({app.config["MAX_FILES_PER_STORAGE"]})'}), 400
            except Exception as e:
                logger.error(f"Ошибка при подсчете файлов в {link_id}: {str(e)}")
                # Не блокируем загрузку, если не удалось посчитать файлы

        # Проверка общего лимита хранилища
        chunk_size = file.content_length
        if current_size + total_size > app.config['MAX_STORAGE_SIZE']:
            logger.warning(f"Превышен лимит хранилища {link_id} при загрузке файла {original_filename}")
            return jsonify({'error': f'Превышен лимит хранилища ({MAX_STORAGE_SIZE_MB} MB)'}), 400

        # Проверка максимального размера файла
        if total_size > app.config['MAX_FILE_SIZE']:
            logger.warning(f"Попытка загрузки слишком большого файла в {link_id}: {original_filename} ({total_size} байт)")
            return jsonify({'error': f'Файл слишком большой (макс. {MAX_FILE_SIZE_MB} MB)'}), 413

        # Путь к временному файлу для сборки чанков
        temp_file_path = os.path.join(storage_path, f"upload_{upload_session_id}.part")
        final_file_path = os.path.join(storage_path, original_filename)

        # Записываем чанк во временный файл
        try:
            # Используем 'ab' для добавления данных в конец файла
            with open(temp_file_path, 'ab') as f:
                chunk_data = file.read()
                f.write(chunk_data)
        except IOError as e:
            logger.error(f"Ошибка записи чанка {chunk_number} для файла {original_filename} в {link_id}: {str(e)}")
            # Попытка удалить временный файл при ошибке записи
            if os.path.exists(temp_file_path):
                try:
                    os.remove(temp_file_path)
                except OSError as remove_err:
                    logger.error(f"Не удалось удалить временный файл {temp_file_path} после ошибки записи: {str(remove_err)}")
            return jsonify({'error': 'Ошибка записи файла на сервере'}), 500

        # Проверяем, все ли чанки загружены
        if chunk_number == total_chunks - 1:
            # Проверяем размер собранного файла
            try:
                actual_size = os.path.getsize(temp_file_path)
                if actual_size != total_size:
                    logger.error(f"Несоответствие размера файла {original_filename} в {link_id}. Ожидалось: {total_size}, получено: {actual_size}")
                    # Удаляем временный файл
                    try:
                        os.remove(temp_file_path)
                    except OSError as e:
                        logger.error(f"Не удалось удалить некорректный временный файл {temp_file_path}: {str(e)}")
                    return jsonify({'error': 'Ошибка сборки файла: несоответствие размера'}), 500

                # Переименовываем временный файл в окончательное имя
                try:
                    # Удаляем старый файл, если он существует (перезапись)
                    if os.path.exists(final_file_path):
                         # Добавим проверку, не является ли это тем же файлом (маловероятно, но на всякий случай)
                         if not os.path.samefile(temp_file_path, final_file_path):
                             os.remove(final_file_path)
                         else:
                             # Если временный и конечный файл - это одно и то же (очень маловероятно),
                             # просто логируем и считаем успешным
                             logger.warning(f"Попытка переименовать файл сам в себя: {final_file_path}")

                    # Если файлы разные или конечного не существует, переименовываем
                    if not os.path.exists(final_file_path) or not os.path.samefile(temp_file_path, final_file_path):
                        os.rename(temp_file_path, final_file_path)

                    logger.info(f"Файл {original_filename} успешно собран и сохранен в {link_id}")
                except OSError as e:
                    logger.error(f"Ошибка переименования временного файла {temp_file_path} в {final_file_path}: {str(e)}")
                    # Пытаемся удалить временный файл в случае ошибки
                    if os.path.exists(temp_file_path):
                        try:
                            os.remove(temp_file_path)
                        except OSError as remove_err:
                            logger.error(f"Не удалось удалить временный файл {temp_file_path} после ошибки переименования: {str(remove_err)}")
                    return jsonify({'error': 'Ошибка сохранения файла на сервере'}), 500

            except OSError as e:
                logger.error(f"Ошибка проверки размера или переименования файла {original_filename} в {link_id}: {str(e)}")
                # Попытка удалить временный файл
                if os.path.exists(temp_file_path):
                     try:
                          os.remove(temp_file_path)
                     except OSError as remove_err:
                          logger.error(f"Не удалось удалить временный файл {temp_file_path} после ошибки проверки: {str(remove_err)}")
                return jsonify({'error': 'Ошибка обработки файла на сервере'}), 500

        return jsonify({'success': True, 'message': f'Chunk {chunk_number + 1}/{total_chunks} uploaded successfully'}), 200

    except Exception as e:
        # Используем handle_error для логирования и безопасного ответа
        error_message = handle_error(e, log_message=f"Критическая ошибка при загрузке файла в {link_id}")
        # Попытка удалить временный файл при любой критической ошибке
        # temp_file_path может быть не определен, если ошибка произошла раньше
        try:
            if 'temp_file_path' in locals() and os.path.exists(temp_file_path):
                 os.remove(temp_file_path)
        except Exception as remove_err:
             logger.error(f"Не удалось удалить временный файл {locals().get('temp_file_path')} после критической ошибки: {remove_err}")
        return jsonify({'error': error_message}), 500


@app.route('/<link_id>/set-theme', methods=['POST'])
@csrf_protected
def set_theme_route(link_id):
    """Установка темы для пользователя, связанного с link_id"""
    try:
        # Проверка на безопасность link_id
        if not re.match(r'^[a-zA-Z0-9_-]+$', link_id):
            logger.warning(f"Попытка установки темы с некорректным link_id: {link_id}")
            return jsonify({'error': 'Недействительный идентификатор хранилища'}), 400

        # Проверяем валидность хранилища (хотя для темы это не обязательно, но для консистентности)
        if not is_temp_storage_valid(link_id):
            logger.warning(f"Попытка установки темы для недействительного хранилища: {link_id}")
            # Не возвращаем ошибку, просто не сохраняем тему в БД, если хранилище невалидно
            return jsonify({'success': True, 'message': 'Хранилище недействительно, тема не сохранена в БД'}), 200

        data = request.get_json()
        if not data or 'theme' not in data:
            logger.warning(f"Некорректные данные при установке темы для {link_id}")
            return jsonify({'error': 'Отсутствуют данные темы'}), 400

        theme = data['theme']
        if theme not in ['light', 'dark']:
            logger.warning(f"Некорректное значение темы '{theme}' для {link_id}")
            return jsonify({'error': 'Некорректное значение темы'}), 400

        # Получаем user_id по link_id
        user_id = get_user_id_by_link_id(link_id)

        if user_id:
            # Сохраняем тему в БД
            success = set_user_theme(user_id, theme)
            if success:
                logger.info(f"Тема '{theme}' успешно установлена для пользователя {user_id} (через link_id {link_id})")
                return jsonify({'success': True})
            else:
                logger.error(f"Не удалось сохранить тему '{theme}' для пользователя {user_id} (через link_id {link_id})")
                return jsonify({'error': 'Ошибка сохранения темы в базе данных'}), 500
        else:
            # Если user_id не найден (анонимная ссылка), просто возвращаем успех
            # Тема будет сохранена на фронтенде через localStorage или data-атрибут
            logger.info(f"Тема '{theme}' установлена на фронтенде для анонимного хранилища {link_id} (не сохранена в БД)")
            return jsonify({'success': True, 'message': 'Тема установлена локально (анонимный пользователь)'})

    except Exception as e:
        error_message = handle_error(e, log_message=f"Критическая ошибка при установке темы для {link_id}")
        return jsonify({'error': error_message}), 500

@app.route('/<link_id>/delete-all', methods=['POST'])
@csrf_protected
def delete_all_files(link_id):
    """Удаление всего временного хранилища"""
    try:
        # Проверка на безопасность link_id
        if not re.match(r'^[a-zA-Z0-9_-]+$', link_id):
            logger.warning(f"Попытка удаления всего хранилища с некорректным link_id: {link_id}")
            return jsonify({'error': 'Недействительный идентификатор хранилища'}), 400

        storage_path = get_temp_storage_path(link_id)

        # Проверка безопасности пути
        real_storage_path = os.path.abspath(storage_path)
        real_base_dir = os.path.abspath(TEMP_STORAGE_DIR)
        if not real_storage_path.startswith(real_base_dir) or real_storage_path == real_base_dir:
            logger.error(f"Попытка удаления директории вне {TEMP_STORAGE_DIR}: {storage_path}")
            return jsonify({'error': 'Доступ запрещен'}), 403

        # Удаляем директорию хранилища, если она существует
        if os.path.exists(storage_path):
            try:
                shutil.rmtree(storage_path)
                logger.info(f"Хранилище {link_id} полностью удалено")
            except OSError as e:
                logger.error(f"Ошибка при удалении хранилища {link_id}: {str(e)}")
                return jsonify({'error': 'Ошибка при удалении хранилища на сервере'}), 500

        # Удаляем запись из базы данных асинхронно
        @run_async
        async def remove_link_from_db():
            try:
                async with aiosqlite.connect(DB_PATH) as conn:
                    await conn.execute('DELETE FROM temp_links WHERE link_id = ?', (link_id,))
                    await conn.commit()
                    logger.info(f"Запись о хранилище {link_id} удалена из БД")
            except Exception as e:
                logger.error(f"Ошибка при удалении записи о хранилище {link_id} из БД: {str(e)}")

        try:
            remove_link_from_db()
        except Exception as e:
            # Логируем ошибку, но не прерываем основной ответ
             logger.error(f"Ошибка при запуске асинхронного удаления записи из БД для {link_id}: {str(e)}")

        return jsonify({'success': True})

    except Exception as e:
        error_message = handle_error(e, log_message=f"Критическая ошибка при удалении хранилища {link_id}")
        return jsonify({'error': error_message}), 500


@app.route('/<link_id>/download-multiple', methods=['POST'])
@csrf_protected
def download_multiple_files(link_id):
    """Скачивание нескольких файлов в виде ZIP-архива"""
    try:
        # Проверка на безопасность link_id
        if not re.match(r'^[a-zA-Z0-9_-]+$', link_id):
            logger.warning(f"Попытка скачивания архива с некорректным link_id: {link_id}")
            return jsonify({'error': 'Недействительный идентификатор хранилища'}), 400

        # Проверяем валидность хранилища
        if not is_temp_storage_valid(link_id):
            logger.warning(f"Попытка скачивания архива из недействительного хранилища: {link_id}")
            return jsonify({'error': 'Хранилище недействительно или срок его действия истек'}), 404

        data = request.get_json()
        if not data or 'filenames' not in data or not isinstance(data['filenames'], list):
            logger.warning(f"Некорректные данные при запросе на скачивание архива для {link_id}")
            return jsonify({'error': 'Отсутствует или некорректен список файлов'}), 400

        filenames = data['filenames']
        if not filenames:
            return jsonify({'error': 'Список файлов пуст'}), 400

        storage_path = get_temp_storage_path(link_id)
        real_storage_path = os.path.abspath(storage_path)

        # Проверяем существование и валидность всех запрошенных файлов
        files_to_zip = []
        for filename in filenames:
            # Декодируем имя файла
            decoded_filename = unquote(filename)

            # Базовая проверка безопасности
            if '..' in decoded_filename or decoded_filename.startswith('/'):
                logger.warning(f"Обнаружена попытка path traversal при скачивании архива: {decoded_filename}")
                return jsonify({'error': f'Недопустимое имя файла: {filename}'}), 400
            if len(decoded_filename) > 255:
                 logger.warning(f"Слишком длинное имя файла при скачивании архива: {len(decoded_filename)}")
                 return jsonify({'error': f'Слишком длинное имя файла: {filename}'}), 400

            file_path = os.path.join(storage_path, decoded_filename)
            real_file_path = os.path.abspath(file_path)

            # Проверка безопасности пути и существования файла
            if not real_file_path.startswith(real_storage_path):
                logger.error(f"Попытка доступа к файлу вне хранилища при скачивании архива: {file_path}")
                return jsonify({'error': f'Доступ к файлу запрещен: {filename}'}), 403
            if not os.path.exists(file_path) or not os.path.isfile(file_path):
                logger.warning(f"Файл не найден или не является файлом при скачивании архива: {file_path}")
                return jsonify({'error': f'Файл не найден: {filename}'}), 404

            files_to_zip.append({'path': file_path, 'name': decoded_filename})

        # Создаем ZIP-архив в памяти
        memory_file = BytesIO()
        with zipfile.ZipFile(memory_file, 'w', zipfile.ZIP_DEFLATED) as zf:
            for file_info in files_to_zip:
                try:
                    zf.write(file_info['path'], arcname=file_info['name'])
                    logger.debug(f"Добавлен файл {file_info['name']} в архив для {link_id}")
                except Exception as e:
                    logger.error(f"Ошибка добавления файла {file_info['name']} в архив для {link_id}: {str(e)}")
                    return jsonify({'error': f'Ошибка при добавлении файла в архив: {file_info["name"]}'}), 500

        memory_file.seek(0)
        zip_filename = f"storage_{link_id}_files.zip"
        logger.info(f"Отправка ZIP-архива {zip_filename} для хранилища {link_id}")

        return send_file(
            memory_file,
            mimetype='application/zip',
            as_attachment=True,
            download_name=zip_filename
        )

    except Exception as e:
        error_message = handle_error(e, log_message=f"Критическая ошибка при скачивании архива для {link_id}")
        return jsonify({'error': error_message}), 500


@app.route('/<link_id>/delete/<filename>', methods=['POST'])
@csrf_protected
def delete_file(link_id, filename):
    """Удаление файла из временного хранилища"""
    try:
        # Проверка на безопасность link_id
        if not re.match(r'^[a-zA-Z0-9_-]+$', link_id):
            logger.warning(f"Попытка удаления с некорректным link_id: {link_id}")
            return jsonify({'error': 'Недействительный идентификатор хранилища'}), 400

        # Проверяем валидность хранилища
        if not is_temp_storage_valid(link_id):
            logger.warning(f"Попытка удаления из недействительного хранилища: {link_id}")
            # Не возвращаем ошибку, если хранилище уже недействительно, просто логируем
            return jsonify({'success': True, 'message': 'Хранилище недействительно, файл не удален (или уже удален)'})

        # Декодируем имя файла из URL
        decoded_filename = unquote(filename)
        logger.info(f"Запрос на удаление файла (декодированный): {decoded_filename} из хранилища {link_id}")

        # Базовая проверка безопасности декодированного имени файла
        if '..' in decoded_filename or decoded_filename.startswith('/'):
            logger.warning(f"Обнаружена попытка path traversal при удалении: {decoded_filename}")
            return jsonify({'error': 'Недопустимое имя файла'}), 400

        # Проверка длины имени файла
        if len(decoded_filename) > 255:
            logger.warning(f"Слишком длинное имя файла при удалении: {len(decoded_filename)}")
            return jsonify({'error': 'Слишком длинное имя файла'}), 400

        storage_path = get_temp_storage_path(link_id)
        # Используем декодированное имя для пути к файлу
        file_path = os.path.join(storage_path, decoded_filename)
        logger.debug(f"Полный путь к удаляемому файлу: {file_path}")

        # Проверка безопасности пути
        real_file_path = os.path.abspath(file_path)
        real_storage_path = os.path.abspath(storage_path)
        if not real_file_path.startswith(real_storage_path):
            logger.error(f"Попытка удаления файла вне хранилища: {file_path}")
            return jsonify({'error': 'Доступ запрещен'}), 403

        # Удаляем файл, если он существует
        if os.path.exists(file_path):
            try:
                if os.path.isfile(file_path):
                    logger.info(f"Попытка удаления файла: {file_path}")
                    os.remove(file_path)
                    # Проверяем, удалился ли файл
                    if not os.path.exists(file_path):
                        logger.info(f"Файл {decoded_filename} успешно удален из хранилища {link_id}")
                        return jsonify({'success': True})
                    else:
                        logger.error(f"Файл {file_path} не удалился после вызова os.remove()")
                        return jsonify({'error': 'Не удалось подтвердить удаление файла'}), 500
                else:
                    logger.warning(f"Попытка удалить не файл: {file_path}")
                    return jsonify({'error': 'Указанный путь не является файлом'}), 400
            except OSError as e:
                logger.error(f"Ошибка при удалении файла {decoded_filename} из {link_id}: {str(e)}")
                return jsonify({'error': 'Ошибка при удалении файла на сервере'}), 500
        else:
            # Если файла нет, считаем операцию успешной (возможно, он уже удален)
            logger.warning(f"Файл {decoded_filename} не найден для удаления в {link_id} (возможно, уже удален)")
            # Дополнительное логирование: список файлов в директории
            try:
                files_in_dir = os.listdir(storage_path)
                logger.debug(f"Файлы в директории {storage_path} при попытке удаления: {files_in_dir}")
            except Exception as list_err:
                logger.error(f"Не удалось получить список файлов в {storage_path} при удалении: {list_err}")
            return jsonify({'success': True, 'message': 'Файл не найден'})

    except Exception as e:
        error_message = handle_error(e, log_message=f"Критическая ошибка при удалении файла {filename} из {link_id}")
        return jsonify({'error': error_message}), 500

if __name__ == '__main__':
    # Проверяем подключение к базе данных
    @run_async
    async def check_db_connection():
        try:
            async with aiosqlite.connect(DB_PATH) as conn:
                logger.info("Подключение к базе данных успешно")
        except Exception as e:
            logger.error(f"Ошибка подключения к базе данных: {str(e)}")
            raise
    
    try:
        # Инициализация базы данных и проверка подключения
        init_db()
        check_db_connection()
        
        # Проверяем существование и права директорий
        if not os.path.exists(TEMP_STORAGE_DIR):
            os.makedirs(TEMP_STORAGE_DIR, exist_ok=True)
            logger.info(f"Создана директория для временных хранилищ: {TEMP_STORAGE_DIR}")
        
        # Запускаем поток очистки
        cleanup_thread = threading.Thread(target=periodic_cleanup, daemon=True)
        cleanup_thread.start()
        logger.info("Запущен поток периодической очистки истекших хранилищ и сессий")
        
        # Запускаем сервер
        logger.info("Запуск веб-сервера на 127.0.0.1:5000")
        app.run(host='127.0.0.1', port=5000, threaded=True, debug=False)
    except Exception as e:
        logger.critical(f"Критическая ошибка при запуске сервера: {str(e)}")
        raise