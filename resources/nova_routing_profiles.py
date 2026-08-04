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
                "NovaGram.exe", "NovaGram", "novagram.exe", "novagram",
                "telegram desktop.exe", "telegram desktop",
            ),
            process_path_regex=r"(?i).*[\\/](telegram|ayugram|novagram|telegram desktop)[\\/].*",
            updater_path_regex=r"(?i).*[\\/](telegram|ayugram|novagram|telegram desktop)[\\/]updater\.exe$",
            ip_glob_patterns=("telegram*.txt", "ip_telegram*.txt"),
            domain_glob_patterns=("telegram*.txt",),
            # "novagram" is not a substring of any other marker here, and no
            # other marker is a substring of it, so a NovaGram install matches
            # this profile and nothing else. In particular it does not collide
            # with Nova's own Nova.exe.
            path_markers=("telegram", "ayugram", "novagram", "tdesktop"),
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
        "ide": AppRoutingProfile(
            key="ide",
            display_name="IDE",
            process_names=(
                "OpenCode.exe", "OpenCode", "opencode.exe", "opencode",
                "Code.exe", "code.exe",
                "Cursor.exe", "cursor.exe",
                "Windsurf.exe", "windsurf.exe",
                "Antigravity.exe", "antigravity.exe",
                "Codex.exe", "codex.exe",
            ),
            process_path_regex=r"(?i).*[\\/](opencode|vscode|code|cursor|windsurf|antigravity|codex)[\\/].*",
            path_markers=("opencode", "vscode", "code.exe", "cursor", "windsurf", "antigravity", "codex"),
        ),
        "cli": AppRoutingProfile(
            key="cli",
            display_name="CLI",
            process_names=(
                "cmd.exe", "powershell.exe", "pwsh.exe",
                "WindowsTerminal.exe", "windowsterminal.exe",
                "opencode-cli.exe", "codex-cli.exe", "gemini-cli.exe", "gemini.exe",
            ),
            process_path_regex=r"(?i).*[\\/](cmd|powershell|pwsh|windowsterminal|opencode-cli|codex-cli|gemini-cli|gemini)(?:\.exe)?$",
            path_markers=("cmd.exe", "powershell.exe", "pwsh.exe", "windowsterminal", "opencode-cli", "codex-cli", "gemini-cli", "gemini.exe"),
        ),
        "obs": AppRoutingProfile(
            key="obs",
            display_name="OBS",
            process_names=(
                "obs64.exe", "obs32.exe", "OBS Studio.exe",
            ),
            process_path_regex=r"(?i).*[\\/](obs64|obs32|obs-studio)[\\/].*",
            path_markers=("obs64.exe", "obs32.exe", "obs-studio"),
        ),
        "games": AppRoutingProfile(
            key="games",
            display_name="Games",
            process_names=(
                "PathOfExile.exe", "pathofexile.exe",
                "PathOfExile_x64.exe", "pathofexile_x64.exe",
                "PathOfExile_KG.exe", "pathofexile_kg.exe",
                "PathOfExile_x64_KG.exe", "pathofexile_x64_kg.exe",
                "Client.exe", "client.exe",
            ),
            process_path_regex=r"(?i).*(path[- ]?of[- ]?exile|poe).*(?:\.exe)?$",
            path_markers=("pathofexile", "path of exile", "poe"),
        ),
    }


def match_app_by_process_path(process_path):
    path_value = str(process_path or "").strip().lower()
    if not path_value:
        return None
    process_name = path_value.replace("/", "\\").rsplit("\\", 1)[-1]
    if process_name in {"pathofexilesteam.exe", "pathofexile_x64steam.exe"}:
        return "GamesDirect"
    for profile in get_default_app_routing_profiles().values():
        for marker in profile.path_markers:
            if marker and marker in path_value:
                return profile.display_name
    return None
