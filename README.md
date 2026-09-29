# ARGUS v0.2

## Что это
Минималистичный инструмент для автоматизированной разведки и анализа безопасности.
Работает на чистом Python без внешних бинарников.
Использует локальную LLM (Ollama) для анализа находок.

## Установка
ollama pull qwen2.5:3b
pip install -r requirements.txt

## Запуск
python argus.py run

## CLI-режим (неинтерактивный)
```bash
python argus.py run --target example.com --mode 2
python argus.py run --target example.com --mode a --output report.html
python argus.py run --target example.com --mode q --no-ai