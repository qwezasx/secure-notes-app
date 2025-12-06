import os
import secrets
from datetime import datetime
from functools import wraps

from dotenv import load_dotenv
from flask import (
    Flask, render_template, request, redirect, 
    url_for, flash, session, g
)

from flask import abort
from flask_wtf import CSRFProtect
from markupsafe import Markup
import bleach

load_dotenv()

app = Flask(__name__)
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'fallback-secret-key')
app.config['WTF_CSRF_ENABLED'] = True
app.config['WTF_CSRF_TIME_LIMIT'] = 3600
app.config['WTF_CSRF_SSL_STRICT'] = False

# Настройки сессии
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SECURE'] = False
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'

# Инициализация CSRF защиты
csrf = CSRFProtect(app)

# Импорт моделей и форм
from models import db, Note, User
from forms import LoginForm, RegisterForm, NoteForm

# Конфигурация базы данных
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('DATABASE_URL', 'sqlite:///notes.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db.init_app(app)

# Создание таблиц
with app.app_context():
    db.create_all()

# Безопасные заголовки middleware
@app.after_request
def set_security_headers(response):
    nonce = getattr(g, 'csp_nonce', 'fallback-nonce')
    
    csp_policy = (
        f"default-src 'self'; "
        f"script-src 'self' 'nonce-{nonce}'; "
        f"style-src 'self'; "
        f"img-src 'self' data:; "
        f"font-src 'self'; "
        f"connect-src 'self'; "
        f"frame-ancestors 'none'; "
        f"base-uri 'self'; "
        f"form-action 'self'"
    )
    
    response.headers['Content-Security-Policy'] = csp_policy
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Server'] = 'Secure Web Server'
    
    return response

@app.before_request
def set_csp_nonce():
    if 'csp_nonce' not in session:
        session['csp_nonce'] = secrets.token_urlsafe(32)
    g.csp_nonce = session['csp_nonce']

@app.context_processor
def inject_nonce():
    return dict(nonce=getattr(g, 'csp_nonce', ''))

# 🔐 БЕЗОПАСНЫЕ функции с параметризованными запросами

def secure_authenticate(username, password):
    """БЕЗОПАСНАЯ функция аутентификации"""
    try:
        user = User.query.filter_by(username=username, password=password).first()
        return user
    except Exception as e:
        app.logger.error(f"Ошибка аутентификации: {e}")
        return None

def secure_register(username, password):
    """БЕЗОПАСНАЯ функция регистрации"""
    try:
        # Проверяем существование пользователя
        existing_user = User.query.filter_by(username=username).first()
        if existing_user:
            return False, "Пользователь уже существует"
        
        # Создаем нового пользователя
        new_user = User(username=username, password=password)
        db.session.add(new_user)
        db.session.commit()
        return True, "Регистрация успешна"
        
    except Exception as e:
        db.session.rollback()
        app.logger.error(f"Ошибка регистрации: {e}")
        return False, "Ошибка регистрации"

def secure_search_users(search_term):
    """БЕЗОПАСНЫЙ поиск пользователей"""
    try:
        # Безопасный поиск с экранированием
        if not search_term or len(search_term) > 50:
            return []
            
        users = User.query.filter(User.username.like(f'%{search_term}%')).all()
        return [(user.username, user.password) for user in users]
    except Exception as e:
        app.logger.error(f"Ошибка поиска: {e}")
        return []

# Декоратор для проверки аутентификации
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user' not in session:
            flash('Пожалуйста, войдите в систему.', 'error')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

# БЕЗОПАСНЫЕ endpoints

@app.route('/login', methods=['GET', 'POST'])
def login():
    """БЕЗОПАСНЫЙ вход в систему"""
    form = LoginForm()
    
    if form.validate_on_submit():
        username = form.username.data
        password = form.password.data
        
        # Валидация входных данных
        if len(username) > 50 or len(password) > 100:
            flash('Некорректные данные', 'error')
            return render_template('login.html', form=form)
        
        user = secure_authenticate(username, password)
        
        if user:
            session['user'] = user.username
            flash(f'Добро пожаловать, {user.username}!', 'success')
            return redirect(url_for('index'))
        else:
            flash('Неверное имя пользователя или пароль', 'error')
    
    return render_template('login.html', form=form)

@app.route('/register', methods=['GET', 'POST'])
def register():
    """БЕЗОПАСНАЯ регистрация"""
    form = RegisterForm()
    
    if form.validate_on_submit():
        username = form.username.data
        password = form.password.data
        
        # Валидация
        if len(username) < 3 or len(username) > 50:
            flash('Имя пользователя должно быть от 3 до 50 символов', 'error')
            return render_template('register.html', form=form)
            
        if len(password) < 3:
            flash('Пароль должен быть не менее 3 символов', 'error')
            return render_template('register.html', form=form)
        
        success, message = secure_register(username, password)
        
        if success:
            flash(message, 'success')
            return redirect(url_for('login'))
        else:
            flash(message, 'error')
    
    return render_template('register.html', form=form)

@app.route('/search')
@login_required
def search():
    """БЕЗОПАСНЫЙ поиск пользователей"""
    search_term = request.args.get('q', '')
    users = []
    
    if search_term:
        # Ограничение длины поискового запроса
        if len(search_term) > 50:
            flash('Слишком длинный поисковый запрос', 'error')
        else:
            users = secure_search_users(search_term)
    
    return render_template('search.html',
                         users=users,
                         search_term=search_term,
                         user=session.get('user'))

# Главная страница
@app.route('/', methods=['GET', 'POST'])
@login_required
def index():
    form = NoteForm()
    
    if form.validate_on_submit():
        title = bleach.clean(form.title.data.strip())
        content = form.content.data
        
        new_note = Note(
            title=title,
            content=content,
            owner=session.get('user'),
            created_at=datetime.utcnow()
        )
        
        db.session.add(new_note)
        db.session.commit()
        
        flash('Заметка успешно создана!', 'success')
        return redirect(url_for('index'))
    
    # Получаем заметки с отладочной информацией
    current_user = session.get('user')
    notes = Note.query.filter_by(owner=current_user).order_by(Note.created_at.desc()).all()
    
    print(f"🔍 Отладка: Пользователь '{current_user}', найдено заметок: {len(notes)}")
    for note in notes:
        print(f"   - Заметка {note.id}: '{note.title}'")
    
    return render_template('index.html', form=form, notes=notes, user=session.get('user'))

@app.route('/edit/<int:note_id>', methods=['GET', 'POST'])
@login_required
def edit(note_id):
    """Редактирование заметки"""
    note = Note.query.get_or_404(note_id)
    
    # Проверяем, что пользователь является владельцем заметки
    if note.owner != session.get('user'):
        flash('У вас нет прав для редактирования этой заметки.', 'error')
        return redirect(url_for('index'))
    
    form = NoteForm(obj=note)
    
    if form.validate_on_submit():
        note.title = bleach.clean(form.title.data.strip())
        note.content = form.content.data
        db.session.commit()
        
        flash('Заметка успешно обновлена!', 'success')
        return redirect(url_for('index'))
    
    return render_template('edit.html', form=form, note=note, user=session.get('user'))

@app.route('/delete/<int:note_id>', methods=['POST'])
@login_required
def delete(note_id):
    """Удаление заметки"""
    note = Note.query.get_or_404(note_id)
    
    # Проверяем, что пользователь является владельцем заметки
    if note.owner != session.get('user'):
        flash('У вас нет прав для удаления этой заметки.', 'error')
        return redirect(url_for('index'))
    
    db.session.delete(note)
    db.session.commit()
    
    flash('Заметка успешно удалена!', 'success')
    return redirect(url_for('index'))

# Выход
@app.route('/logout')
def logout():
    session.pop('user', None)
    session.pop('csp_nonce', None)
    flash('Вы вышли из системы.', 'info')
    return redirect(url_for('login'))

@app.route('/test')
def test():
    return render_template('test.html')

# Favicon
@app.route('/favicon.ico')
def favicon():
    return '', 204

# Обработчики ошибок
@app.errorhandler(404)
def not_found_error(error):
    return render_template('error.html', error_code=404, error_message='Страница не найдена'), 404

@app.errorhandler(500)
def internal_error(error):
    db.session.rollback()
    return render_template('error.html', error_code=500, error_message='Внутренняя ошибка сервера'), 500

def insecure_demo_function():
    
    # 1. Критическая уязвимость: eval (выполнение произвольного кода)
    malicious_code = "__import__('os').system('echo Dangerous!')"
    result = eval(malicious_code)  # Bandit: B307 (eval used)
    
    # 2. Критическая: хардкод секретного ключа
    secret_key = "super_secret_password_12345"  # Bandit: B105
    
    # 3. Критическая: SQL инъекция через конкатенацию строк
    user_input = "1; DROP TABLE users; --"
    sql_query = "SELECT * FROM users WHERE id = " + user_input  # Bandit: B608
    
    # 4. Критическая: pickle десериализация
    import pickle
    untrusted_data = b"cos\nsystem\n(S'rm -rf /'\ntR."
    pickle.loads(untrusted_data)  # Bandit: B301
    
    # 5. Средняя: небезопасный random для безопасности
    import random
    session_token = random.randint(1000, 9999)  # Bandit: B311
    
    return "⚠️ Демонстрация уязвимостей завершена"

if __name__ == '__main__':
    import os
    print("🛡️  Запуск ЗАЩИЩЕННОГО приложения")
    print("📍 Адрес: http://127.0.0.1:5000")
    print("👤 Тестовые пользователи: admin/admin123, user1/password1")
    
    # Безопасно: debug только из переменных окружения
    debug_enabled = os.environ.get('FLASK_DEBUG', 'False').lower() == 'true'
    app.run(debug=True, host='127.0.0.1', port=5000)

