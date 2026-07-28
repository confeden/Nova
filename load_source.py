import os
import sys
import shutil
import subprocess
from pathlib import Path
from nova_metadata import read_project_version

# --- КОНФИГУРАЦИЯ ---
PROJECT_DIR = Path(__file__).parent
MAIN_FILE = PROJECT_DIR / "nova.pyw"
REPO_URL = "https://github.com/confeden/Nova.git"

# Список файлов, которые НУЖНО отправлять на GitHub.
WHITELIST_RULES = """
# 1. Скрываем всё
*

# 2. Разрешаем только это:
!nova.pyw
!LICENSE
!README.md

# Разрешаем папку автообновления
!.github/
!.github/workflows/
!.github/workflows/publish_update.yml
"""

def pause_and_exit(code=0):
    """Останавливаем выполнение, чтобы пользователь прочитал лог"""
    print("\n" + "="*40)
    input("👉 Нажмите Enter, чтобы закрыть окно...")
    sys.exit(code)

def get_version():
    """Читаем версию из nova.pyw"""
    if not MAIN_FILE.exists():
        print("❌ Ошибка: nova.pyw не найден!")
        pause_and_exit(1)
    return read_project_version(PROJECT_DIR, default="unknown")

def run_git(args, error_msg):
    """Запуск git команд с обработкой ошибок"""
    try:
        subprocess.run(["git"] + args, cwd=PROJECT_DIR, check=True)
    except subprocess.CalledProcessError as e:
        print(f"\n❌ {error_msg}")
        print(f"Детали ошибки: {e}")
        pause_and_exit(1)
    except FileNotFoundError:
        print("\n❌ Ошибка: Git не установлен или не найден в PATH.")
        pause_and_exit(1)

def main():
    try:
        print("=== ОБНОВЛЕНИЕ ИСХОДНОГО КОДА НА GITHUB ===")
        
        # 1. Проверка версии
        version = get_version()
        print(f"📌 Версия проекта: {version}")
        
        print("\n⚠️  ВНИМАНИЕ: Это действие сбросит историю Git и отправит чистый код.")
        
        # Если хотите запускать без вопроса, закомментируйте блок ниже
        choice = input(f"🚀 Обновить GitHub до версии {version}? (y/n): ").lower()
        if choice != 'y':
            print("Отмена пользователем.")
            pause_and_exit(0)

        # 2. Удаление старой папки .git
        git_dir = PROJECT_DIR / ".git"
        if git_dir.exists():
            print("🧹 Очистка старой истории git...")
            try:
                os.system(f'rmdir /S /Q "{git_dir}"')
            except Exception as e:
                print(f"⚠️ Не удалось удалить папку .git стандартным методом: {e}")

        # 3. Инициализация
        print("⚙️  Инициализация репозитория...")
        run_git(["init"], "Ошибка git init")
        run_git(["branch", "-M", "main"], "Ошибка переименования ветки")
        run_git(["remote", "add", "origin", REPO_URL], "Ошибка добавления remote")

        # 4. Настройка исключений (Невидимый щит)
        info_exclude = git_dir / "info" / "exclude"
        info_exclude.parent.mkdir(parents=True, exist_ok=True)
        
        with open(info_exclude, "w", encoding="utf-8") as f:
            f.write(WHITELIST_RULES)
        
        # 5. Добавление и отправка
        print("📦 Упаковка файлов...")
        run_git(["add", "."], "Ошибка git add")
        
        msg = f"Source update v{version}"
        run_git(["commit", "-m", msg], "Ошибка git commit")
        
        print("🚀 Отправка на сервер (Force Push)...")
        run_git(["push", "-u", "origin", "main", "--force"], "Ошибка git push")

        print(f"\n✅ УСПЕХ! Код обновлен до версии {version}.")
        print("🔗 Ссылка: https://github.com/confeden/Nova")
        
    except Exception as e:
        print(f"\n❌ Непредвиденная ошибка скрипта: {e}")
        pause_and_exit(1)

    # Финальная пауза в случае успеха
    pause_and_exit(0)

if __name__ == "__main__":
    main()
