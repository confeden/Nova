//! Background general checks own their sockets and never change system routes or VPN settings.

#[cfg(windows)]
mod backend;
#[cfg(windows)]
mod platform;
pub mod policy;
#[cfg(windows)]
mod transport;
#[cfg(windows)]
mod worker;

pub(crate) type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

pub fn capabilities() -> serde_json::Value {
    serde_json::json!({"protocol":1,"native_general":true,"max_candidates":policy::MAX_CANDIDATES})
}

pub fn run() -> i32 {
    #[cfg(windows)]
    {
        match worker::run() {
            Ok(()) => 0,
            Err(error) => {
                eprintln!("[General] Проверка остановлена: {error}");
                1
            }
        }
    }
    #[cfg(not(windows))]
    {
        eprintln!("general-background requires Windows");
        2
    }
}
