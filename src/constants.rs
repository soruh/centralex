use std::time::Duration;

pub const AUTH_TIMEOUT: Duration = Duration::from_secs(30);
pub const CALL_ACK_TIMEOUT: Duration = Duration::from_secs(30);
pub const CALL_TIMEOUT: Duration = Duration::from_secs(24 * 60 * 60);
pub const PORT_RETRY_TIME: Duration = Duration::from_secs(15 * 60);
pub const PORT_OWNERSHIP_TIMEOUT: Duration = Duration::from_secs(60 * 60);
pub const PING_TIMEOUT: Duration = Duration::from_secs(30);
pub const SEND_PING_INTERVAL: Duration = Duration::from_secs(20);

pub const CACHE_STORE_INTERVAL: Duration = Duration::from_secs(5);
