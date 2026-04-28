from dataclasses import dataclass
from functools import lru_cache


@dataclass(frozen=True)
class AppRoutingProfile:
    key: str
    display_name: str
    process_names: tuple[str, ...]
    process_path_regex: str
    updater_path_regex: str | None = None
    ip_glob_patterns: tuple[str, ...] = ()
    domain_glob_patterns: tuple[str, ...] = ()
    path_markers: tuple[str, ...] = ()


@lru_cache(maxsize=1)
def get_default_app_routing_profiles():
    return {
        "discord": AppRoutingProfile(
            key="discord",
            display_name="Discord",
            process_names=(
                "Discord.exe", "Discord", "discord.exe", "discord",
                "DiscordCanary.exe", "DiscordCanary", "discordcanary.exe", "discordcanary",
                "DiscordPTB.exe", "DiscordPTB", "discordptb.exe", "discordptb",
            ),
            process_path_regex=r"(?i).*[\\/](discord|discordcanary|discordptb)[\\/].*",
            updater_path_regex=r"(?i).*[\\/](discord|discordcanary|discordptb)[\\/]update\.exe$",
            ip_glob_patterns=("discord*.txt",),
            domain_glob_patterns=("discord*.txt",),
            path_markers=("discord",),
        ),
        "telegram": AppRoutingProfile(
            key="telegram",
            display_name="Telegram",
            process_names=(
                "Telegram.exe", "Telegram", "telegram.exe", "telegram",
                "AyuGram.exe", "AyuGram", "ayugram.exe", "ayugram",
                "telegram desktop.exe", "telegram desktop",
            ),
            process_path_regex=r"(?i).*[\\/](telegram|ayugram|telegram desktop)[\\/].*",
            updater_path_regex=r"(?i).*[\\/](telegram|ayugram|telegram desktop)[\\/]updater\.exe$",
            ip_glob_patterns=("telegram*.txt", "ip_telegram*.txt"),
            domain_glob_patterns=("telegram*.txt",),
            path_markers=("telegram", "ayugram", "tdesktop"),
        ),
        "whatsapp": AppRoutingProfile(
            key="whatsapp",
            display_name="WhatsApp",
            process_names=(
                "WhatsApp.exe", "WhatsApp", "whatsapp.exe", "whatsapp",
                "WhatsApp.Root.exe", "WhatsApp.Root", "whatsapp.root.exe", "whatsapp.root",
            ),
            process_path_regex=r"(?i).*(whatsappdesktop|whatsapp(?:\.root)?(?:\.exe)?).*",
            ip_glob_patterns=("whatsapp*.txt",),
            domain_glob_patterns=("whatsapp*.txt",),
            path_markers=("whatsapp", "whatsappdesktop"),
        ),
        "opencode": AppRoutingProfile(
            key="opencode",
            display_name="OpenCode",
            process_names=(
                "OpenCode.exe", "OpenCode", "opencode.exe", "opencode",
                "opencode-cli.exe", "opencode-cli",
            ),
            process_path_regex=r"(?i).*[\\/]opencode[\\/].*",
            path_markers=("opencode",),
        ),
    }


def match_app_by_process_path(process_path):
    path_value = str(process_path or "").strip().lower()
    if not path_value:
        return None
    for profile in get_default_app_routing_profiles().values():
        for marker in profile.path_markers:
            if marker and marker in path_value:
                return profile.display_name
    return None
