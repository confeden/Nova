"""Скачать собранный на GitHub nova-tls-terminator.exe в bin/.

Этот бинарник — единственная часть Nova, которой нужен C-тулчейн: BoringSSL, а
к нему cmake, MSVC, NASM и LLVM. Собирать его локально означает держать всё это
на машине и терять возможность выпустить релиз после переустановки Windows.
Поэтому его собирает GitHub (см. .github/workflows/build_tls_terminator.yml), а
здесь остаётся только скачать готовый файл и проверить хэш.

Обычно этот скрипт запускать не нужно: Inno.py вызывает `ensure()` сам при
каждой сборке установщика. Вручную — когда хочется проверить или обновить
отдельно:

    python fetch_tls_terminator.py            # скачать, если нужно
    python fetch_tls_terminator.py --force    # перекачать всегда
    python fetch_tls_terminator.py --check    # только проверить, ничего не качая

Без этого файла приложение работает: терминатор необязателен, и при его
отсутствии релей остаётся на прежнем TLS-пути.
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


class FetchError(RuntimeError):
    """Не удалось получить файл. Отдельный тип, чтобы вызывающий мог отличить
    «нет сети» от «нет файла» и решить, можно ли продолжать."""


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


def local_sha256() -> str:
    """Хэш того, что уже лежит, или пустая строка."""
    if not os.path.exists(TARGET):
        return ""
    return sha256_of(TARGET)


def published_sha256(timeout: float = 20.0) -> str:
    """Хэш опубликованной сборки. Поднимает FetchError, если недоступен."""
    try:
        return _get(f"{BASE}/{FILENAME}.sha256", timeout=timeout).decode("ascii", "replace").strip().lower()
    except urllib.error.HTTPError as err:
        raise FetchError(
            f"релиз {TAG!r} в {REPO} не отвечает ({err.code}). "
            "Запустите Actions -> Build TLS terminator с галочкой publish."
        ) from err
    except Exception as err:
        raise FetchError(f"сеть недоступна: {err}") from err


def ensure(force: bool = False, log=print, timeout: float = 180.0) -> str:
    """Привести bin/ в соответствие с опубликованной сборкой.

    Возвращает путь к файлу. Поднимает FetchError, если файла нет и скачать его
    не удалось — вызывающий решает, фатально это или нет. Если файл на месте, а
    сеть недоступна, это не ошибка: сборка офлайн должна оставаться возможной.
    """
    have = local_sha256()
    try:
        expected = published_sha256()
    except FetchError as err:
        if have:
            # Уже есть рабочий файл. Отсутствие сети не повод не собирать
            # установщик — повод сказать, что свежесть не проверена.
            log(f"[TLS] Не удалось проверить свежесть терминатора ({err}). Использую имеющийся.")
            return TARGET
        raise

    if have == expected and not force:
        return TARGET

    log(f"[TLS] {'Обновляю' if have else 'Скачиваю'} {FILENAME} из {REPO}@{TAG}...")
    try:
        payload = _get(f"{BASE}/{FILENAME}", timeout=timeout)
    except Exception as err:
        if have:
            log(f"[TLS] Скачать не удалось ({err}). Использую имеющийся файл.")
            return TARGET
        raise FetchError(f"не удалось скачать: {err}") from err

    got = hashlib.sha256(payload).hexdigest()
    if got != expected:
        # Хэш опубликован рядом с файлом тем же прогоном сборки. Совпадения
        # достаточно, чтобы отвергнуть повреждённую по дороге загрузку; доверие
        # к самой сборке — это доверие к GitHub и к репозиторию.
        raise FetchError(
            f"хэш не совпал, файл не сохранён.\n  ожидался {expected}\n  получен  {got}"
        )

    os.makedirs(os.path.dirname(TARGET), exist_ok=True)
    # Через временный файл: прерванная запись не должна оставить обрезанный
    # exe, который потом молча попадёт в установщик.
    temporary = TARGET + ".part"
    with open(temporary, "wb") as handle:
        handle.write(payload)
    os.replace(temporary, TARGET)
    log(f"[TLS] Готово: {TARGET} ({len(payload)} байт)")
    return TARGET


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--force", action="store_true", help="перекачать даже если хэш совпадает")
    parser.add_argument("--check", action="store_true", help="только сообщить состояние")
    args = parser.parse_args()

    if args.check:
        have = local_sha256()
        if not have:
            print(f"нет: {TARGET}")
            print("выполните: python fetch_tls_terminator.py")
            return 1
        print(f"есть: {TARGET}")
        print(f"  sha256 {have}")
        try:
            expected = published_sha256()
        except FetchError as err:
            print(f"  свежесть не проверена: {err}")
            return 0
        print("  актуально" if have == expected else f"  устарело, опубликован {expected}")
        return 0

    try:
        path = ensure(force=args.force)
    except FetchError as err:
        print(f"[TLS] {err}")
        return 2
    print(f"актуально: {path}")
    print(f"  sha256 {local_sha256()}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
