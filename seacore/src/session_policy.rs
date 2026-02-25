use std::time::Duration;

#[derive(Clone, Debug)]
pub struct SessionGovernancePolicy {
    pub handshake_timeout: Duration,
    pub connection_idle_timeout: Duration,
    pub half_close_timeout: Duration,
}

const DEFAULT_HANDSHAKE_TIMEOUT_SECS: u64 = 5;
const DEFAULT_CONNECTION_IDLE_TIMEOUT_SECS: u64 = 10;
const DEFAULT_HALF_CLOSE_TIMEOUT_SECS: u64 = 2;

impl SessionGovernancePolicy {
    pub fn from_config(
        handshake_timeout_secs: Option<u64>,
        connection_idle_timeout_secs: Option<u64>,
        legacy_max_idle_time_secs: Option<u64>,
        half_close_timeout_secs: Option<u64>,
    ) -> Self {
        let handshake_timeout = Duration::from_secs(
            handshake_timeout_secs
                .unwrap_or(DEFAULT_HANDSHAKE_TIMEOUT_SECS)
                .max(1),
        );

        let connection_idle_timeout = Duration::from_secs(
            connection_idle_timeout_secs
                .or(legacy_max_idle_time_secs)
                .unwrap_or(DEFAULT_CONNECTION_IDLE_TIMEOUT_SECS)
                .max(1),
        );

        let half_close_timeout = Duration::from_secs(
            half_close_timeout_secs
                .unwrap_or(DEFAULT_HALF_CLOSE_TIMEOUT_SECS)
                .max(1),
        );

        Self {
            handshake_timeout,
            connection_idle_timeout,
            half_close_timeout,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn from_config_prefers_new_idle_timeout_over_legacy() {
        let policy = SessionGovernancePolicy::from_config(Some(7), Some(11), Some(42), Some(3));
        assert_eq!(policy.handshake_timeout, Duration::from_secs(7));
        assert_eq!(policy.connection_idle_timeout, Duration::from_secs(11));
        assert_eq!(policy.half_close_timeout, Duration::from_secs(3));
    }

    #[test]
    fn from_config_uses_legacy_idle_timeout_when_new_absent() {
        let policy = SessionGovernancePolicy::from_config(None, None, Some(15), None);
        assert_eq!(
            policy.connection_idle_timeout,
            Duration::from_secs(15),
            "legacy max_idle_time_secs should remain backward compatible"
        );
    }

    #[test]
    fn from_config_applies_safe_minimum_of_one_second() {
        let policy = SessionGovernancePolicy::from_config(Some(0), Some(0), Some(0), Some(0));
        assert_eq!(policy.handshake_timeout, Duration::from_secs(1));
        assert_eq!(policy.connection_idle_timeout, Duration::from_secs(1));
        assert_eq!(policy.half_close_timeout, Duration::from_secs(1));
    }
}
