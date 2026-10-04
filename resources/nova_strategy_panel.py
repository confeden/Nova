"""Контрольная панель для оценки стратегии general.

С 1.42 general применяется ко всем сайтам вне списков, поэтому стратегию
нужно оценивать не только по тому, сколько заблокированного она открывает,
но и по тому, не ломает ли она то, что работало без обхода.

Замер 2026-10-04 (стенд из 50 рабочих сайтов): прежние general и ai
(multisplit/split2 + seqovl) оставляли apple.com, microsoft.com,
cloudflare.com, docs.docker.com, jetbrains.com и ещё пять сайтов висеть на
15-24 КБ — без стратегии те же сайты отдавали 200-1300 КБ. Это реакция ТСПУ на
соединение к зарубежному хостингу, в ClientHello которого он не разобрал SNI.
Панель ниже — сайты с крупной главной страницей (больше 24 КБ, иначе замирание
не наблюдаемо) на тех же хостингах: Akamai, Cloudflare, CloudFront, Fastly.
"""

CONTROL_DOMAINS = (
    "www.apple.com",
    "www.microsoft.com",
    "www.cloudflare.com",
    "docs.docker.com",
    "www.jetbrains.com",
    "github.com",
    "www.dropbox.com",
    "www.twitch.tv",
    "pypi.org",
    "store.epicgames.com",
    "www.google.com",
    "duckduckgo.com",
)


def control_domains(direct_ok_hot=(), limit=20):
    """Панель: посещаемые сайты, открывшиеся без обхода, затем встроенные.

    Посещаемые идут первыми: именно их пользователь и заметит сломанными.
    """
    out, seen = [], set()
    for d in list(direct_ok_hot) + list(CONTROL_DOMAINS):
        d = (d or "").strip().lower()
        if not d or d in seen:
            continue
        seen.add(d)
        out.append(d)
        if len(out) >= limit:
            break
    return out

