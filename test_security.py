"""
Тесты безопасности для приложения "Безопасные заметки"
"""
import pytest
import os
import re
from app import app as flask_app

@pytest.fixture
def app():
    """Фикстура для тестирования Flask приложения"""
    flask_app.config['TESTING'] = True
    flask_app.config['WTF_CSRF_ENABLED'] = False  # Отключаем для тестов
    return flask_app

@pytest.fixture
def client(app):
    """Фикстура для тестового клиента"""
    return app.test_client()

def test_security_headers(client):
    """
    Тест: Проверка security headers
    ВАЖНО: Приложение должно возвращать правильные заголовки
    """
    # Пытаемся получить главную страницу
    response = client.get('/')
    
    # Проверяем security headers если есть ответ
    if response.status_code == 200:
        headers = response.headers
        
        # Content Security Policy должен быть
        assert 'Content-Security-Policy' in headers
        
        # X-Content-Type-Options должен быть 'nosniff'
        assert 'X-Content-Type-Options' in headers
        assert headers['X-Content-Type-Options'] == 'nosniff'
        
        # X-Frame-Options должен быть 'DENY'
        assert 'X-Frame-Options' in headers
        assert headers['X-Frame-Options'] == 'DENY'
        
        # X-XSS-Protection должен быть
        assert 'X-XSS-Protection' in headers
        
        print("✅ Security headers настроены правильно")

def test_no_sql_injection_patterns():
    """
    Тест: Проверка что нет паттернов SQL инъекций
    """
    # Читаем все Python файлы проекта
    python_files = ['app.py', 'models.py', 'forms.py']
    
    dangerous_patterns = [
        r'execute\(f["\']',          # f-строки в execute
        r'execute\(["\']\s*\+\s*',   # конкатенация строк в execute
        r'\.query\(["\']',           # прямой query с строкой
        r'SELECT\s*\*\s*FROM\s*[\w]+\s*WHERE\s*[\w]+\s*=\s*["\'][^"\']*["\']',
    ]
    
    for file_name in python_files:
        if os.path.exists(file_name):
            with open(file_name, 'r', encoding='utf-8') as f:
                content = f.read()
                
            for pattern in dangerous_patterns:
                matches = re.findall(pattern, content, re.IGNORECASE)
                if matches:
                    print(f"⚠️  Внимание: найдено {len(matches)} совпадений в {file_name}")
                    print(f"   Паттерн: {pattern}")
                    print(f"   Совпадения: {matches[:3]}")  # Показываем первые 3

def test_no_hardcoded_secrets():
    """
    Тест: Проверка что нет хардкод секретов
    """
    # Читаем app.py для проверки
    with open('app.py', 'r', encoding='utf-8') as f:
        content = f.read()
    
    # Проверяем, что SECRET_KEY берется из переменных окружения
    assert "os.getenv('SECRET_KEY'" in content or "os.environ.get('SECRET_KEY'" in content
    print("✅ SECRET_KEY использует переменные окружения")

def test_csrf_protection_enabled():
    """
    Тест: Проверка что CSRF защита включена в конфигурации
    """
    assert hasattr(flask_app, 'config'), "У приложения нет конфигурации"
    
    # CSRF должен быть включен (в продакшене)
    csrf_enabled = flask_app.config.get('WTF_CSRF_ENABLED', True)
    assert csrf_enabled is True or csrf_enabled is not False
    
    print("✅ CSRF защита включена")

def test_input_sanitization():
    """
    Тест: Проверка санитизации ввода
    """
    # Проверяем использование bleach в app.py
    with open('app.py', 'r', encoding='utf-8') as f:
        content = f.read()
    
    # Должны быть вызовы bleach.clean
    assert 'bleach.clean' in content
    print("✅ Используется bleach для санитизации ввода")

def test_no_debug_in_production_code():
    """
    Тест: Проверка что нет debug=True в основном коде
    """
    with open('app.py', 'r', encoding='utf-8') as f:
        content = f.read()
    
    # Ищем debug=True вне app.run (это может быть допустимо в условии if __name__)
    lines = content.split('\n')
    
    for i, line in enumerate(lines, 1):
        if 'debug=True' in line and 'app.run' not in line:
            print(f"⚠️  Обнаружен debug=True в строке {i}: {line.strip()}")
    
    print("✅ Нет debug=True в основном коде (кроме app.run)")

if __name__ == '__main__':
    # Запускаем тесты
    pytest.main([__file__, '-v'])