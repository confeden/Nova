"""Как писать в `temp/` так, чтобы это не стоило и не росло.

`temp/` читает не человек, а тот, кто разбирает отчёт о проблеме. Поэтому у
файлов там два требования, и оба нарушались.

**Цена записи.** Помощники писали строку так: `os.makedirs(..., exist_ok=True)`,
затем `open(path, "a")`, запись, закрытие — три системных вызова плюс проверка
каталога на **каждую строку**. Замерено здесь, 3000 строк:

    как было (makedirs + open + close)   684 мс   228 мкс/строка
    open + close без makedirs            382 мс   127 мкс/строка
    удержанный handle + flush             11 мс     3.8 мкс/строка   <- взято
    удержанный handle, буфер ОС           0.5 мс    0.2 мкс/строка

Взят третий. Первый вариант дороже в **60 раз** без всякой пользы. Четвёртый
дешевле ещё в двадцать, но теряет хвост при жёстком убийстве процесса — а хвост
это ровно то, ради чего лог и читают.

**Размер.** Ротации не было нигде. `NovaDivertRedirect.log.startup.log`
открывался на дозапись при каждом запуске и не усекался никогда: 98 КБ
накопленного stdout на машине разработчика. Лог, который не помещается в глаза,
бесполезен так же, как отсутствующий.

Обрезка здесь **на месте, а не в отдельный файл**: `.1`, `.2` рядом — это
беспорядок, а хвост и есть то, что нужно. Проверка размера идёт по счётчику в
памяти, без `stat` на каждую запись.
"""

import os
import threading

__all__ = ["CappedLog", "DEFAULT_CAP", "DEFAULT_KEEP", "trim_to_tail"]

# Двух мегабайт хватает на несколько часов самого болтливого помощника, и это
# всё ещё файл, который можно прочитать целиком.
DEFAULT_CAP = 2 * 1024 * 1024
# После обрезки остаётся половина: слишком маленький хвост теряет предысторию
# события, слишком большой заставляет обрезать снова через минуту.
DEFAULT_KEEP = 1024 * 1024

_TRIM_MARK = "--- начало файла обрезано, оставлен хвост ---\n"


def trim_to_tail(path, keep_bytes):
    """Оставить в файле последние `keep_bytes` и пометку об обрезке.

    Читается кусок с конца и переписывается на место. Обрезка редка (раз на
    мегабайты), поэтому цена одной такой операции значения не имеет.
    """
    try:
        size = os.path.getsize(path)
    except OSError:
        return 0
    if size <= keep_bytes:
        return size
    try:
        with open(path, "rb") as f:
            f.seek(size - int(keep_bytes))
            tail = f.read()
        # До первого перевода строки — обрывок, читать его незачем.
        cut = tail.find(b"\n")
        if 0 <= cut < len(tail) - 1:
            tail = tail[cut + 1 :]
        with open(path, "wb") as f:
            f.write(_TRIM_MARK.encode("utf-8"))
            f.write(tail)
        return os.path.getsize(path)
    except OSError:
        return size


class CappedLog:
    """Открытый один раз файл с потолком по размеру.

    Потокобезопасен: помощники пишут из нескольких потоков.
    """

    __slots__ = ("path", "cap", "keep", "_handle", "_size", "_lock")

    def __init__(self, path, cap_bytes=DEFAULT_CAP, keep_bytes=DEFAULT_KEEP, truncate=False):
        self.path = str(path)
        self.cap = int(cap_bytes)
        self.keep = min(int(keep_bytes), int(cap_bytes))
        self._lock = threading.Lock()
        self._handle = None
        self._size = 0
        self._open(truncate=bool(truncate))

    def _open(self, truncate=False):
        directory = os.path.dirname(self.path)
        if directory:
            # Один раз за жизнь файла, а не на каждую строку.
            os.makedirs(directory, exist_ok=True)
        if truncate:
            self._size = 0
            self._handle = open(self.path, "w", encoding="utf-8", newline="")
            return
        self._size = trim_to_tail(self.path, self.keep) if os.path.exists(self.path) else 0
        self._handle = open(self.path, "a", encoding="utf-8", newline="")

    def write(self, message):
        """Записать строку. Перевод строки добавляется, если его нет."""
        line = str(message)
        if not line.endswith("\n"):
            line += "\n"
        data = line.encode("utf-8", errors="replace")
        with self._lock:
            handle = self._handle
            if handle is None:
                return
            try:
                handle.write(line)
                handle.flush()
            except (OSError, ValueError):
                return
            self._size += len(data)
            if self._size > self.cap:
                self._rotate_locked()

    def _rotate_locked(self):
        try:
            self._handle.close()
        except (OSError, ValueError):
            pass
        self._handle = None
        self._size = trim_to_tail(self.path, self.keep)
        try:
            self._handle = open(self.path, "a", encoding="utf-8", newline="")
        except OSError:
            self._handle = None

    def close(self):
        with self._lock:
            if self._handle is not None:
                try:
                    self._handle.close()
                except (OSError, ValueError):
                    pass
                self._handle = None

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()
        return False
