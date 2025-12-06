#!/usr/bin/env python3
"""
Анализ отчета Bandit для GitHub Actions
Блокирует мерж при обнаружении HIGH severity уязвимостей
"""

import json
import sys
import os

def main():
    """Основная функция анализа"""
    report_file = 'bandit-report.json'
    
    if not os.path.exists(report_file):
        print("⚠️ Файл отчета Bandit не найден")
        sys.exit(0)  # Не блокируем, если нет отчета
    
    try:
        with open(report_file, 'r', encoding='utf-8') as f:
            data = json.load(f)
        
        issues = data.get('results', [])
        
        # Считаем уязвимости по критичности
        high_issues = [i for i in issues if i.get('issue_severity') == 'HIGH']
        medium_issues = [i for i in issues if i.get('issue_severity') == 'MEDIUM']
        low_issues = [i for i in issues if i.get('issue_severity') == 'LOW']
        
        print("📊 РЕЗУЛЬТАТЫ СКАНИРОВАНИЯ БЕЗОПАСНОСТИ")
        print("=" * 50)
        print(f"🔴 ВЫСОКАЯ критичность: {len(high_issues)}")
        print(f"🟡 СРЕДНЯЯ критичность: {len(medium_issues)}")
        print(f"🟢 НИЗКАЯ критичность: {len(low_issues)}")
        print(f"📝 Всего проблем: {len(issues)}")
        
        # Показываем критические проблемы
        if high_issues:
            print("\n❌ КРИТИЧЕСКИЕ УЯЗВИМОСТИ (блокируют мерж):")
            for idx, issue in enumerate(high_issues[:5], 1):
                print(f"\n{idx}. {issue.get('test_name', 'Unknown')}")
                print(f"   📄 Файл: {issue.get('filename')}:{issue.get('line_number')}")
                print(f"   📝 Описание: {issue.get('issue_text', 'No description')}")
                if issue.get('code'):
                    print(f"   🔧 Код: {issue.get('code')}")
            
            print(f"\n🚫 БЛОКИРОВКА: Найдено {len(high_issues)} критических уязвимостей")
            sys.exit(1)  # Блокируем мерж
        else:
            print("\n✅ ПРОЙДЕНО: Критических уязвимостей не найдено")
            sys.exit(0)  # Разрешаем мерж
            
    except json.JSONDecodeError:
        print("❌ Ошибка чтения JSON отчета")
        sys.exit(1)
    except Exception as e:
        print(f"⚠️ Неизвестная ошибка: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
