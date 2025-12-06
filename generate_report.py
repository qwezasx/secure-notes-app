#!/usr/bin/env python3
"""
Генерация отчета безопасности
"""

import json
from datetime import datetime

def generate_security_report():
    """Генерирует отчет безопасности"""
    try:
        with open('bandit-report.json', 'r', encoding='utf-8') as f:
            data = json.load(f)
        
        issues = data.get('results', [])
        high_count = len([i for i in issues if i.get('issue_severity') == 'HIGH'])
        medium_count = len([i for i in issues if i.get('issue_severity') == 'MEDIUM'])
        low_count = len([i for i in issues if i.get('issue_severity') == 'LOW'])
        
        report = f"""# 📋 ОТЧЕТ О БЕЗОПАСНОСТИ

## Проект: Безопасные заметки
## Дата: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

### Результаты сканирования Bandit:

- 🔴 **Критические уязвимости:** {high_count}
- 🟡 **Средние уязвимости:** {medium_count}
- 🟢 **Низкие уязвимости:** {low_count}
- 📊 **Всего проблем:** {len(issues)}

"""
        
        if high_count > 0:
            report += "### 🔴 КРИТИЧЕСКИЕ ПРОБЛЕМЫ:\n\n"
            for idx, issue in enumerate(issues[:3], 1):
                if issue.get('issue_severity') == 'HIGH':
                    report += f"{idx}. **{issue.get('test_name')}**\n"
                    report += f"   - Файл: `{issue.get('filename')}:{issue.get('line_number')}`\n"
                    report += f"   - Описание: {issue.get('issue_text')}\n\n"
        
        report += """### 📋 РЕКОМЕНДАЦИИ:

1. **Регулярно обновляйте зависимости** - используйте `safety check` или `pip-audit`
2. **Используйте секреты из переменных окружения** - никогда не хардкодите пароли
3. **Проводите регулярные security review** кода
4. **Настройте pre-commit хуки** для автоматической проверки
5. **Тестируйте на проникновение** (pentesting) перед релизом

---
*Отчет сгенерирован автоматически GitHub Actions Pipeline*
"""
        
        return report
        
    except FileNotFoundError:
        return "# 📋 ОТЧЕТ О БЕЗОПАСНОСТИ\n\nФайл отчета не найден.\n"
    except Exception as e:
        return f"# 📋 ОТЧЕТ О БЕЗОПАСНОСТИ\n\nОшибка генерации отчета: {e}\n"

if __name__ == "__main__":
    report_content = generate_security_report()
    with open('SECURITY_REPORT.md', 'w', encoding='utf-8') as f:
        f.write(report_content)
    print("✅ Отчет безопасности сгенерирован")
