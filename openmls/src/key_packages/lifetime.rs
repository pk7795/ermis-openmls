#[cfg(not(target_arch = "wasm32"))]
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use tls_codec::{TlsDeserialize, TlsDeserializeBytes, TlsSerialize, TlsSize};

use super::key_package_in::LifetimeValidationTime;

#[cfg(test)]
use std::cell::Cell;

#[cfg(test)]
thread_local! {
    static TEST_UNIX_TIME_SECONDS: Cell<Option<u64>> = const { Cell::new(None) };
}

#[cfg(test)]
struct TestUnixTimeGuard(Option<u64>);

#[cfg(test)]
impl Drop for TestUnixTimeGuard {
    fn drop(&mut self) {
        TEST_UNIX_TIME_SECONDS.with(|clock| clock.set(self.0));
    }
}

pub(crate) fn unix_time_seconds() -> Option<u64> {
    #[cfg(test)]
    if let Some(unix_time_seconds) = TEST_UNIX_TIME_SECONDS.with(Cell::get) {
        return Some(unix_time_seconds);
    }

    #[cfg(target_arch = "wasm32")]
    {
        checked_js_unix_seconds(js_sys::Date::now())
    }
    #[cfg(not(target_arch = "wasm32"))]
    {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|duration| duration.as_secs())
            .ok()
            .filter(|seconds| *seconds > 0)
    }
}

// Check the original JS sample before a timer/cast can saturate NaN or
// negative values to zero. Keep one clock sample per lifetime operation.
#[cfg(any(target_arch = "wasm32", test))]
fn checked_js_unix_seconds(milliseconds: f64) -> Option<u64> {
    if !milliseconds.is_finite() || milliseconds <= 0.0 {
        return None;
    }
    let seconds = (milliseconds / 1000.0).floor();
    if seconds < 1.0 || seconds >= 18_446_744_073_709_551_616.0 {
        return None;
    }
    Some(seconds as u64)
}

/// This value is used as the default lifetime if no default  lifetime is configured.
/// The value is in seconds and amounts to 3 * 28 Days, i.e. about 3 months.
const DEFAULT_KEY_PACKAGE_LIFETIME_SECONDS: u64 = 60 * 60 * 24 * 28 * 3;

/// This value is used as the default amount of time (in seconds) the lifetime
/// of a `KeyPackage` is extended into the past to allow for skewed clocks. The
/// value is in seconds and amounts to 1h.
const DEFAULT_KEY_PACKAGE_LIFETIME_MARGIN_SECONDS: u64 = 60 * 60;

/// The maximum total lifetime range that is acceptable for a leaf node.
/// The value is in seconds and amounts to 3 * 28 Days, i.e., about 3 months.
pub const MAX_LEAF_NODE_LIFETIME_RANGE_SECONDS: u64 =
    DEFAULT_KEY_PACKAGE_LIFETIME_MARGIN_SECONDS + DEFAULT_KEY_PACKAGE_LIFETIME_SECONDS;

/// The lifetime represents the times between which clients will
/// consider a KeyPackage valid. This time is represented as an absolute time,
/// measured in seconds since the Unix epoch (1970-01-01T00:00:00Z).
/// A client MUST NOT use the data in a KeyPackage for any processing before
/// the not_before date, or after the not_after date.
///
/// Applications MUST define a maximum total lifetime that is acceptable for a
/// KeyPackage, and reject any KeyPackage where the total lifetime is longer
/// than this duration.This extension MUST always be present in a KeyPackage.
///
/// ```c
/// // draft-ietf-mls-protocol-16
/// struct {
///     uint64 not_before;
///     uint64 not_after;
/// } Lifetime;
/// ```
#[derive(
    PartialEq,
    Eq,
    Copy,
    Clone,
    Debug,
    TlsSerialize,
    TlsSize,
    TlsDeserialize,
    TlsDeserializeBytes,
    Serialize,
    Deserialize,
)]
pub struct Lifetime {
    not_before: u64,
    not_after: u64,
}

/// Failures creating a signed lifetime. No fallback clock is used.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum LifetimeCreationError {
    /// Clock unavailable or at/before the Unix epoch.
    #[error("invalid lifetime clock")]
    InvalidClock,
    /// Zero, inverted, overflowing, or excessive duration.
    #[error("invalid lifetime range")]
    InvalidRange,
}

impl Lifetime {
    /// Create a signed lifetime using one fallible current-clock sample.
    pub fn try_new(t: u64) -> Result<Self, LifetimeCreationError> {
        let now = unix_time_seconds().ok_or(LifetimeCreationError::InvalidClock)?;
        Self::try_new_at(t, now)
    }

    /// Create a lifetime at an explicit Unix timestamp, with the existing 1h margin.
    pub fn try_new_at(t: u64, now: u64) -> Result<Self, LifetimeCreationError> {
        if now == 0 {
            return Err(LifetimeCreationError::InvalidClock);
        }
        if t == 0 {
            return Err(LifetimeCreationError::InvalidRange);
        }
        let not_before = now.saturating_sub(DEFAULT_KEY_PACKAGE_LIFETIME_MARGIN_SECONDS);
        let not_after = now
            .checked_add(t)
            .ok_or(LifetimeCreationError::InvalidRange)?;
        let lifetime = Self {
            not_before,
            not_after,
        };
        if !lifetime.has_acceptable_range() {
            return Err(LifetimeCreationError::InvalidRange);
        }
        Ok(lifetime)
    }

    /// Fallible default for production KeyPackage builders.
    pub fn try_default() -> Result<Self, LifetimeCreationError> {
        Self::try_new(DEFAULT_KEY_PACKAGE_LIFETIME_SECONDS)
    }

    pub(crate) fn current_time() -> Option<u64> {
        unix_time_seconds()
    }

    /// Legacy infallible constructor. Production generation uses `try_new`.
    /// Create a new lifetime with lifetime `t` (in seconds).
    /// Note that the lifetime is extended 1h into the past to adapt to skewed
    /// clocks, i.e. `not_before` is set to now - 1h.
    pub fn new(t: u64) -> Self {
        let lifetime_margin: u64 = DEFAULT_KEY_PACKAGE_LIFETIME_MARGIN_SECONDS;
        let now = match unix_time_seconds() {
            Some(now) => now,
            None => {
                log::error!("SystemTime before UNIX EPOCH.");
                0
            }
        };
        let not_before = now.saturating_sub(lifetime_margin);
        let not_after = now.saturating_add(t);
        Self {
            not_before,
            not_after,
        }
    }

    /// Initialize raw lifetime without skew and explicit dates.
    pub const fn init(not_before: u64, not_after: u64) -> Self {
        Self {
            not_before,
            not_after,
        }
    }

    /// Returns true if this lifetime is valid.
    pub fn is_valid(&self) -> bool {
        self.is_valid_for(LifetimeValidationTime::CurrentTime)
    }

    pub(crate) fn is_valid_for(&self, validation_time: LifetimeValidationTime) -> bool {
        let elapsed = match validation_time {
            LifetimeValidationTime::CurrentTime => unix_time_seconds(),
            LifetimeValidationTime::ServerAcceptedAt(elapsed) => Some(elapsed),
        };

        match elapsed {
            Some(elapsed) => self.is_valid_at(elapsed),
            None => {
                log::error!("SystemTime before UNIX EPOCH.");
                false
            }
        }
    }

    /// Returns whether `unix_time_seconds` is strictly inside this lifetime.
    /// RFC 9420 represents both limits as an open interval for this check.
    pub fn is_valid_at(&self, unix_time_seconds: u64) -> bool {
        self.not_before < unix_time_seconds && unix_time_seconds < self.not_after
    }

    #[cfg(test)]
    pub(crate) fn with_test_unix_time<T>(unix_time_seconds: u64, action: impl FnOnce() -> T) -> T {
        let previous = TEST_UNIX_TIME_SECONDS.with(|clock| clock.replace(Some(unix_time_seconds)));
        let _guard = TestUnixTimeGuard(previous);
        action()
    }

    /// ValSem(openmls/annotations#32):
    /// Applications MUST define a maximum total lifetime that is acceptable for a LeafNode,
    /// and reject any LeafNode where the total lifetime is longer than this duration.
    pub fn has_acceptable_range(&self) -> bool {
        matches!(self.not_after.checked_sub(self.not_before),
            Some(range) if range > 0 && range <= MAX_LEAF_NODE_LIFETIME_RANGE_SECONDS)
    }

    /// Returns the "not before" timestamp of the KeyPackage.
    pub fn not_before(&self) -> u64 {
        self.not_before
    }

    /// Returns the "not after" timestamp of the KeyPackage.
    pub fn not_after(&self) -> u64 {
        self.not_after
    }
}

impl Default for Lifetime {
    fn default() -> Self {
        Lifetime::new(DEFAULT_KEY_PACKAGE_LIFETIME_SECONDS)
    }
}

#[cfg(test)]
mod tests {
    use tls_codec::{Deserialize, Serialize};

    use super::Lifetime;

    #[test]
    fn lifetime() -> Result<(), tls_codec::Error> {
        // A freshly created extensions must be valid.
        let ext = Lifetime::default();
        assert!(ext.is_valid());

        // An extension without lifetime is invalid (waiting for 1 second).
        let ext = Lifetime::new(0);
        std::thread::sleep(std::time::Duration::from_secs(1));
        assert!(!ext.is_valid());

        // Test (de)serializing invalid extension
        let serialized = ext.tls_serialize_detached()?;
        let ext_deserialized = Lifetime::tls_deserialize(&mut serialized.as_slice())?;
        assert!(!ext_deserialized.is_valid());
        Ok(())
    }

    #[test]
    fn explicit_validation_time_uses_open_interval_boundaries() {
        let lifetime = Lifetime::init(100, 200);

        assert!(!lifetime.is_valid_at(99));
        assert!(!lifetime.is_valid_at(100));
        assert!(lifetime.is_valid_at(101));
        assert!(lifetime.is_valid_at(199));
        assert!(!lifetime.is_valid_at(200));
        assert!(!lifetime.is_valid_at(201));
    }
}

#[cfg(test)]
mod strict_range_tests {
    use super::*;

    #[test]
    fn js_clock_checks_original_sample_before_integer_conversion() {
        for sample in [
            f64::NAN,
            f64::INFINITY,
            f64::NEG_INFINITY,
            -1000.0,
            0.0,
            999.9,
            f64::MAX,
            18_446_744_073_709_551_616.0 * 1000.0,
        ] {
            assert_eq!(checked_js_unix_seconds(sample), None);
        }
        assert_eq!(checked_js_unix_seconds(1000.0), Some(1));
        assert_eq!(checked_js_unix_seconds(1999.9), Some(1));
        assert_eq!(
            checked_js_unix_seconds(1_791_504_123_456.0),
            Some(1_791_504_123)
        );
    }

    #[test]
    fn malformed_and_maximum_ranges_are_checked_without_saturation() {
        for lifetime in [
            Lifetime::init(0, 0),
            Lifetime::init(200, 100),
            Lifetime::init(0, u64::MAX),
            Lifetime::init(1, 7_261_202),
        ] {
            assert!(!lifetime.has_acceptable_range());
        }
        assert!(Lifetime::init(1, 7_261_201).has_acceptable_range());
        assert!(Lifetime::init(u64::MAX - 1, u64::MAX).has_acceptable_range());
    }

    #[test]
    fn production_generation_rejects_zero_overflow_clock_and_excess_range(
    ) -> Result<(), LifetimeCreationError> {
        assert_eq!(
            Lifetime::try_new_at(0, 10_000),
            Err(LifetimeCreationError::InvalidRange)
        );
        assert_eq!(
            Lifetime::try_new_at(1, 0),
            Err(LifetimeCreationError::InvalidClock)
        );
        assert_eq!(
            Lifetime::try_new_at(1, u64::MAX),
            Err(LifetimeCreationError::InvalidRange)
        );
        assert_eq!(
            Lifetime::try_new_at(7_257_601, 10_000),
            Err(LifetimeCreationError::InvalidRange)
        );
        assert_eq!(
            Lifetime::try_new_at(86 * 86400, 10_000),
            Err(LifetimeCreationError::InvalidRange)
        );
        let lifetime = Lifetime::try_new_at(7_257_600, 10_000)?;
        assert_eq!(lifetime.not_after() - lifetime.not_before(), 7_261_200);
        Ok(())
    }

    #[test]
    fn randomized_malformed_lifetimes_match_the_unsigned_range_invariant() {
        let mut seed = 0x1234_5678_9abc_def0_u64;
        for _ in 0..10_000 {
            seed = seed.wrapping_mul(6364136223846793005).wrapping_add(1);
            let before = seed;
            seed = seed.wrapping_mul(6364136223846793005).wrapping_add(1);
            let after = seed;
            let expected = after > before && after - before <= 7_261_200;
            assert_eq!(
                Lifetime::init(before, after).has_acceptable_range(),
                expected
            );
        }
    }
}
