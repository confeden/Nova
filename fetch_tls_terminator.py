"""Скачать собранный на GitHub nova-tls-terminator.exe в bin/.

Этот бинарник — единственная часть Nova, которой нужен C-тулчейн: BoringSSL, а
к нему cmake, MSVC, NASM и LLVM. Собирать его локально означает держать всё это
на машине и терять возможность выпустить релиз после переустановки Windows.
Поэтому его собирает GitHub (см. .github/workflows/build_tls_terminator.yml), а
здесь остаётся только скачать готовый файл и проверить хэш.

    python fetch_tls_terminator.py            # скачать, если нужно
    python fetch_tls_terminator.py --force    # перекачать всегда
    python fetch_tls_terminator.py --check    # только проверить, ничего не качая

Без этого файла приложение работает: терминатор необязателен, и при его
отсутствии релей остаётся на прежнем TLS-пути. Проверка в Inno.py не даст
собрать установщик молча без него.
"""

import argparse
import hashlib
import os
import sys
import urllib.error
import urllib.request

REPO = os.environ.get("NOVA_TLS_TERMINATOR_REPO", "confeden/Nova")
TAG = os.environ.get("NOVA_TLS_TERMINATOR_TAG", "tls-terminator")
FILENAME = "nova-tls-terminator.exe"

BASE = f"https://github.com/{REPO}/releases/download/{TAG}"
ROOT = os.path.dirname(os.path.abspath(__file__))
TARGET = os.path.join(ROOT, "bin", FILENAME)


def _get(url: str, timeout: float = 60.0) -> bytes:
    request = urllib.request.Request(url, headers={"User-Agent": "nova-fetch-tls-terminator"})
    with urllib.request.urlopen(request, timeout=timeout) as response:
        return response.read()


def sha256_of(path: str) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def local_state() -> str:
    if not os.path.exists(TARGET):
        return ""
    return sha256_of(TARGET)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--force", action="store_true", help="перекачать даже если хэш совпадает")
    parser.add_argument("--check", action="store_true", help="только сообщить состояние")
    args = parser.parse_args()

    have = local_state()
    if args.check:
        if not have:
            print(f"нет: {TARGET}")
            print("выполните: python fetch_tls_terminator.py")
            return 1
        print(f"есть: {TARGET}")
        print(f"  sha256 {have}")
        return 0

    try:
        expected = _get(f"{BASE}/{FILENAME}.sha256").decode("ascii", "replace").strip().lower()
    except urllib.error.HTTPError as err:
        print(f"не удалось получить хэш ({err.code}). Релиз {TAG!r} в {REPO} опубликован?")
        print("Запустите Actions -> Build TLS terminator с галочкой publish.")
        return 2
    except Exception as err:
        print(f"сеть недоступна: {err}")
        return 2

    if have == expected and not args.force:
        print(f"актуально: {TARGET}")
        print(f"  sha256 {have}")
        return 0

    print(f"качаю {FILENAME} из {REPO}@{TAG}...")
    try:
        payload = _get(f"{BASE}/{FILENAME}", timeout=180.0)
    except Exception as err:
        print(f"не удалось скачать: {err}")
        return 2

    got = hashlib.sha256(payload).hexdigest()
    if got != expected:
        # Хэш опубликован рядом с файлом тем же прогоном сборки. Совпадения
        # достаточно, чтобы отвергнуть повреждённую или подменённую по дороге
        # загрузку; доверие к самой сборке — это доверие к GitHub и к репозиторию.
        print("хэш не совпал — файл не сохранён.")
        print(f"  ожидался {expected}")
        print(f"  получен  {got}")
        return 3

    os.makedirs(os.path.dirname(TARGET), exist_ok=True)
    # Через временный файл: прерванная запись не должна оставить обрезанный
    # exe, который потом молча попадёт в установщик.
    temporary = TARGET + ".part"
    with open(temporary, "wb") as handle:
        handle.write(payload)
    os.replace(temporary, TARGET)

    print(f"готово: {TARGET}")
    print(f"  {len(payload)} байт, sha256 {got}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
