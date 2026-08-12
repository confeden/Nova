"""Сколько заняла каждая фаза запуска и когда она началась.

Зачем вообще. Жалоба на минутный старт разбиралась вручную: в логе метки времени
с точностью до секунды (`%H:%M:%S`), а весь старт укладывается в 3-8 секунд, так
что «долго» и «мгновенно» в нём выглядят одинаково. Из 46 секунд того запуска 39
приходились на одну фазу, и чтобы это увидеть, пришлось сопоставлять строки
глазами.

Почему не просто «фаза X заняла N мс». Фазы идут параллельно: главный поток
строит окно, сервис поднимает менеджеры, а шестнадцать воркеров стартуют со
ступенчатыми задержками. Плоский список длительностей в такой картине врёт —
сумма получается больше настоящего старта, и непонятно, что кого ждало. Поэтому
у каждой записи две величины: смещение от начала процесса и длительность. По
ним видно и что тормозит, и что с чем перекрывается.

Для воркеров длительность бессмысленна — это бесконечные циклы. У них меряется
другое: насколько фактический старт отстал от запрошенной задержки. Отставание
означает, что потоку не досталось процессора, и это отдельный диагноз.

Цена: два `time.monotonic()` и добавление в список на фазу, порядка сорока фаз
за запуск. Отдельного выключателя нет намеренно — выключенная диагностика это
диагностика, которой не будет в тот единственный раз, когда она нужна.
"""

import json
import os
import threading
import time

# Отсчёт от импорта модуля. Он импортируется из nova.pyw в шапке, до всякой
# работы, так что это практически начало процесса — а точное начало нам и не
# нужно, важны разницы.
_T0 = time.monotonic()

_LOCK = threading.Lock()
_RECORDS = []

# Потолок на случай, если фазой обернут что-нибудь, что вызывается в цикле:
# диагностика не должна становиться утечкой памяти.
_MAX_RECORDS = 400

# Ниже этого фазы не показываются: строка про 0 мс не несёт информации, а таких
# большинство.
_INTERESTING_MS = 50.0


def elapsed_ms():
    return (time.monotonic() - _T0) * 1000.0


def _add(kind, name, offset_ms, duration_ms, detail):
    with _LOCK:
        if len(_RECORDS) >= _MAX_RECORDS:
            return
        _RECORDS.append((kind, str(name), float(offset_ms), duration_ms, str(detail or "")))


class phase:
    """Контекст-менеджер: меряет длительность и запоминает начало.

    Исключение внутри не проглатывается, но фаза всё равно записывается — как
    раз упавшая фаза интереснее всего, и потерять её время значит потерять
    единственный след.
    """

    __slots__ = ("name", "detail", "_start")

    def __init__(self, name, detail=""):
        self.name = name
        self.detail = detail

    def __enter__(self):
        self._start = time.monotonic()
        return self

    def __exit__(self, exc_type, exc, tb):
        began = (self._start - _T0) * 1000.0
        took = (time.monotonic() - self._start) * 1000.0
        detail = self.detail
        if exc_type is not None:
            detail = (detail + " " if detail else "") + f"(упало: {exc_type.__name__})"
        _add("phase", self.name, began, took, detail)
        return False


def note(name, detail=""):
    """Мгновенное событие: точка на шкале без длительности."""
    _add("note", name, elapsed_ms(), None, detail)


def worker_started(name, requested_delay=0.0, scheduled_at_ms=0.0):
    """Воркер проснулся после своей ступенчатой задержки.

    Записывается отставание, а не длительность: у бесконечного цикла её нет.

    `scheduled_at_ms` обязателен по существу, а не для удобства. Задержка
    отсчитывается с момента, когда воркер запланировали, а этот момент — не
    начало процесса: `start_services_threads` запускается примерно через пять
    секунд после старта. Сравнивать время пробуждения (от старта процесса) с
    запрошенной задержкой (от планирования) — значит сравнивать две разные
    точки отсчёта и получать пять секунд несуществующего отставания. Ровно эта
    ошибка дважды выдавала здесь «голодание потоков», которого нет.
    """
    began = elapsed_ms()
    due = float(scheduled_at_ms or 0.0) + float(requested_delay or 0.0) * 1000.0
    _add("worker", name, began, None, "%.0f" % due)
    return began


def _worker_lag(record):
    """На сколько воркер опоздал против срока, к которому должен был проснуться."""
    try:
        return record[2] - float(record[4] or 0.0)
    except Exception:
        return 0.0


def records():
    with _LOCK:
        return list(_RECORDS)


def render(top=12, history=None):
    """Компактный отчёт. Пусто, если мерить нечего.

    `history` — записи прошлых запусков из `append_history`. С ними отчёт может
    сказать не только «фаза заняла N мс», но и «это втрое больше обычного», а
    без них цифра сама по себе ни о чём не говорит: разброс между запусками
    здесь двух-трёхкратный и нормален.
    """
    rows = records()
    if not rows:
        return []

    phases = [r for r in rows if r[0] == "phase" and r[3] is not None]
    notes = [r for r in rows if r[0] == "note"]
    workers = [r for r in rows if r[0] == "worker"]

    lines = []
    slow = sorted((r for r in phases if r[3] >= _INTERESTING_MS),
                  key=lambda r: r[3], reverse=True)[:top]
    if slow:
        # По убыванию длительности, а не по времени: самая дорогая фаза должна
        # быть первой строкой, иначе отчёт снова придётся читать глазами.
        lines.append("[Boot] Фазы запуска (мс), дороже всего сверху:")
        for _kind, name, offset, took, detail in slow:
            tail = f"  {detail}" if detail else ""
            lines.append(f"[Boot]   {took:8.0f} мс  начало +{offset:.0f} мс  {name}{tail}")

    if notes:
        marks = ", ".join(f"{name} +{offset:.0f}" for _k, name, offset, _d, _t in notes[:8])
        lines.append(f"[Boot] Отметки (мс): {marks}")

    if workers:
        worst = max(workers, key=_worker_lag)
        lag = _worker_lag(worst)
        # Отставание, а не просто «последний на +N»: воркеры просыпаются по
        # заданным задержкам, и +16 с само по себе ничего не значит, если так и
        # было задумано. Значение имеет разница.
        lines.append(
            f"[Boot] Воркеров поднято: {len(workers)}, "
            f"худшее отставание {lag:.0f} мс ({worst[1]})"
        )

    total = sum(r[3] for r in phases if r[3] is not None)
    # Промежуток считается по фазам, а не по всем записям. Воркеры просыпаются
    # по намеренным ступенчатым задержкам вплоть до одиннадцати секунд; включать
    # их в промежуток значит делить работу на ожидание и получать заниженную
    # параллельность. На живом прогоне это давало 1.4x вместо 1.6x.
    span = max((r[2] + (r[3] or 0.0)) for r in phases) if phases else 0.0
    if span > 0:
        # Расхождение суммы и промежутка — это и есть мера параллельности. Если
        # они близки, старт фактически последовательный, и его есть смысл
        # раскладывать на потоки.
        lines.append(
            f"[Boot] Суммарно в фазах {total:.0f} мс, промежуток работы {span:.0f} мс "
            f"(параллельность {total / span:.1f}x)"
        )

    # Главное, ради чего копится история: отличить «долго» от «дольше обычного».
    for name, now, med in compare_with_history(history or []):
        lines.append(
            f"[Boot] ОТКЛОНЕНИЕ: {name} — {now:.0f} мс против обычных {med:.0f} "
            f"({now / med:.1f}x)"
        )
    return lines


# Сколько запусков помнить. Двадцати хватает, чтобы медиана перестала прыгать,
# и файл остаётся в несколько килобайт.
HISTORY_LIMIT = 20

# Во сколько раз фаза должна превысить свою же медиану, чтобы это назвали
# отклонением. Порог грубый намеренно: разброс между запусками здесь
# двух-трёхкратный и сам по себе нормален — 10707 мс против 3853 у одной и той
# же фазы на соседних прогонах. Кричать надо только про то, что вышло за эти
# рамки.
OUTLIER_FACTOR = 3.0


def append_history(path, stamp=""):
    """Дописать итоги запуска в JSONL и вернуть прежние записи.

    Ради этого файла всё и затевалось. Один отчёт в логе отвечает «сколько
    заняла фаза сегодня», но не отвечает «это много или обычно» — а
    единственный способ узнать второе состоял в том, чтобы поднять логи прошлых
    запусков и сравнить глазами. Ровно та ручная работа, которую хронология
    должна была убрать.
    """
    rows = [r for r in records() if r[0] == "phase" and r[3] is not None]
    if not rows:
        return []
    previous = read_history(path)
    entry = {
        "stamp": str(stamp or ""),
        "phases": {name: round(dur, 1) for _k, name, _o, dur, _d in rows},
    }
    try:
        os.makedirs(os.path.dirname(path), exist_ok=True)
        kept = (previous + [entry])[-HISTORY_LIMIT:]
        with open(path, "w", encoding="utf-8") as handle:
            for item in kept:
                handle.write(json.dumps(item, ensure_ascii=False) + "\n")
    except Exception:
        pass
    return previous


def read_history(path):
    out = []
    try:
        with open(path, encoding="utf-8") as handle:
            for line in handle:
                line = line.strip()
                if line:
                    out.append(json.loads(line))
    except Exception:
        return []
    return out


def _median(values):
    values = sorted(values)
    if not values:
        return 0.0
    mid = len(values) // 2
    if len(values) % 2:
        return values[mid]
    return (values[mid - 1] + values[mid]) / 2.0


def compare_with_history(previous, minimum_samples=3):
    """Фазы, вышедшие за OUTLIER_FACTOR от своей медианы: [(имя, сейчас, медиана)]."""
    if not previous:
        return []
    history = {}
    for entry in previous:
        for name, value in (entry.get("phases") or {}).items():
            history.setdefault(name, []).append(float(value))
    out = []
    for _k, name, _o, dur, _d in records():
        if _k != "phase" or dur is None:
            continue
        samples = history.get(name) or []
        if len(samples) < minimum_samples:
            continue
        med = _median(samples)
        if med > 0 and dur > med * OUTLIER_FACTOR:
            out.append((name, dur, med))
    out.sort(key=lambda item: item[1] / item[2], reverse=True)
    return out


def reset():
    """Только для тестов."""
    global _T0
    with _LOCK:
        _RECORDS.clear()
        _T0 = time.monotonic()
