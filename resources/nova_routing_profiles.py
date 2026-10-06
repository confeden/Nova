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


# Spotify's own names. The desktop client reaches them over the system proxy (PAC), so the PAC
# routes them by the «Spotify» row too; the rest of its traffic (the access point on :4070, which
# ignores the proxy) is caught by process. akamaized hosts are Spotify's audio CDN by full name.
SPOTIFY_DOMAINS = (
    "spotify.com", "spotify.net", "spotify.link", "spoti.fi", "byspotify.com",
    "scdn.co", "pscdn.co", "spotifycdn.com", "spotifycdn.net",
    "audio-ak-spotify-com.akamaized.net", "audio4-ak-spotify-com.akamaized.net",
    "heads4-ak-spotify-com.akamaized.net",
)

# AI apps — Claude, Codex/ChatGPT, OpenCode (owner, 2026-10-05: through the secondary slot while
# Nova runs). The desktop apps use the system proxy, so the PAC routes these names by the
# «ИИ-приложения» row; the CLIs ignore the system proxy and are caught by process instead. A browser
# on these sites follows the same row: one choice for everything the agents talk to.
AI_APP_DOMAINS = (
    # Anthropic / Claude
    "claude.ai", "claude.com", "claude.site", "clau.de", "claudeusercontent.com", "anthropic.com",
    # OpenAI / ChatGPT / Codex
    "chatgpt.com", "openai.com", "oaistatic.com", "oaiusercontent.com",
    # OpenCode
    "opencode.ai",
)


# Path substrings (lowercase) that mark an AI app. One tuple, read by the process matcher here and
# by tcp_proxy's own family classifier, so the two cannot drift apart.
AI_APP_PATH_MARKERS = (
    "\\windowsapps\\claude_", "\\anthropicclaude\\", "\\claude\\claude-code\\",
    "\\.local\\bin\\claude.exe",
    "\\windowsapps\\openai.", "\\openai\\codex\\", "\\@openai\\codex\\",
    "\\opencode.exe", "\\@opencode-ai",
)


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
        # IDE и CLI сняты с перехвата намеренно. Они существовали только
        # ради доступа к нейросетям внутри редакторов и терминалов, а это
        # решает разблокировка AI через NRPT: подмена DNS, которой перехват
        # трафика не нужен. Профиль CLI вдобавок ловил cmd.exe, powershell,
        # pwsh и WindowsTerminal — то есть весь терминальный трафик машины.
        "obs": AppRoutingProfile(
            key="obs",
            display_name="OBS",
            process_names=(
                "obs64.exe", "obs32.exe", "OBS Studio.exe",
            ),
            process_path_regex=r"(?i).*[\\/](obs64|obs32|obs-studio)[\\/].*",
            path_markers=("obs64.exe", "obs32.exe", "obs-studio"),
        ),
        # Before "games": its "poe" marker is a bare substring and must not get the first look.
        # The Microsoft Store build lives under WindowsApps\SpotifyAB.SpotifyMusic_*; Studio by
        # Spotify Labs ships its own client plus node.exe helpers in its folder, all of it Spotify's.
        "spotify": AppRoutingProfile(
            key="spotify",
            display_name="Spotify",
            process_names=("Spotify.exe", "spotify.exe", "Studio by Spotify Labs.exe"),
            process_path_regex=r"(?i).*([\\/]spotify[\\/]spotify\.exe|spotifyab\.spotifymusic|studio by spotify labs).*",
            path_markers=("\\spotify\\spotify.exe", "spotifyab.spotifymusic", "studio by spotify labs"),
        ),
        # Claude: the Store build under WindowsApps\Claude_* (Claude.exe, cowork-svc.exe), its
        # bundled Claude Code under %APPDATA%\Claude\claude-code\<ver>\claude.exe, the standalone
        # CLI in ~\.local\bin\claude.exe, the old Squirrel build in %LOCALAPPDATA%\AnthropicClaude.
        # Codex/ChatGPT: the Store app WindowsApps\OpenAI.Codex_* (ChatGPT.exe, Codex.exe, codex.exe)
        # and the CLI in %LOCALAPPDATA%\[Programs\]OpenAI\Codex\bin\codex.exe; npm's @openai/codex
        # runs a native codex.exe under its folder. OpenCode: the desktop app OpenCode.exe and npm's
        # opencode-ai, which ships a native opencode.exe. Agents run as plain node.exe (Claude Code
        # from npm) cannot be told apart from any other node by path and are not caught.
        "ai_apps": AppRoutingProfile(
            key="ai_apps",
            display_name="AI Apps",
            process_names=("Claude.exe", "claude.exe", "cowork-svc.exe", "ChatGPT.exe", "Codex.exe",
                           "codex.exe", "OpenCode.exe", "opencode.exe"),
            process_path_regex=r"(?i).*(\\windowsapps\\(claude_|openai\.)|\\anthropicclaude\\|\\claude\\claude-code\\|\\\.local\\bin\\claude\.exe|\\@?openai\\codex\\|\\opencode\.exe|\\@opencode-ai).*",
            path_markers=AI_APP_PATH_MARKERS,
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


VPN_ROUTE_MODES = ("warp", "opera")


def name_in_domains(name, domains):
    """True when `name` is one of `domains` or a subdomain of one."""
    host = str(name or "").strip().lower().lstrip(".")
    return any(host == d or host.endswith("." + d) for d in domains)


def drop_family_names(rules, family_domains):
    """NRPT rules without the names of a family that rides a VPN slot.

    The AI-unlock rules send a name's DNS to an unblocker, whose answer is the unblocker's own
    proxy. Claude Code is redirected by address, so with those rules in place its "secondary VPN"
    connection would reach Anthropic from the unblocker's server, not from the slot's exit.
    """
    return {ns: srvs for ns, srvs in dict(rules or {}).items() if not name_in_domains(ns, family_domains)}
