# Crypto

# CryptoSafe Manager

Учебный проект менеджера паролей с пошаговой реализацией криптографических функций.

## Тестирование

Тесты выполняются с помощью pytest.
Рекомендуемый способ запуска тестов — через IDE (PyCharm) с настроенным виртуальным окружением.

## Архитектура

- core — криптография
- database — схема SQLite и вспомогательные функции
- gui — пользовательский интерфейс на Tkinter
Архитектура следует принципам MVC (Model-View-Controller).

## Установка

```bash
python -m venv venv
venv\Scripts\activate
pip install -r requirements.txt
python src/gui/main_window.py
```


