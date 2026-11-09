use nova_common::models::ServiceId;

pub struct DomainCatalog {
    pub youtube: Vec<String>,
    pub discord: Vec<String>,
    pub ai: Vec<String>,
    pub telegram: Vec<String>,
    pub cloudflare: Vec<String>,
    pub exclude: Vec<String>,
}

fn parse_lines(raw: &str) -> Vec<String> {
    raw.lines()
        .map(|l| l.trim())
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .map(|l| l.to_string())
        .collect()
}

impl DomainCatalog {
    pub fn load_embedded() -> Self {
        let yt_raw = include_str!("../data/list/youtube.txt");
        let discord_raw = include_str!("../data/list/discord.txt");
        let ai_raw = include_str!("../data/list/ai.txt");
        let tg_raw = include_str!("../data/list/telegram.txt");
        let cf_raw = include_str!("../data/list/cloudflare.txt");
        let ex_raw = include_str!("../data/list/exclude.txt");

        Self {
            youtube: parse_lines(yt_raw),
            discord: parse_lines(discord_raw),
            ai: parse_lines(ai_raw),
            telegram: parse_lines(tg_raw),
            cloudflare: parse_lines(cf_raw),
            exclude: parse_lines(ex_raw),
        }
    }

    pub fn get_domains_for_service(&self, service: ServiceId) -> &[String] {
        match service {
            ServiceId::YouTube => &self.youtube,
            ServiceId::Discord => &self.discord,
            ServiceId::Ai => &self.ai,
            ServiceId::Telegram => &self.telegram,
            ServiceId::Cloudflare => &self.cloudflare,
            ServiceId::General => &[],
        }
    }
}
