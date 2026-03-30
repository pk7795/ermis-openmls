//! Platform-aware logging utility.
//!
//! - **Android**: uses `android_logger` → output appears in `logcat`
//! - **iOS / Desktop**: uses `eprintln!` → output appears in Xcode console / stderr

const TAG: &str = "OpenMLS";

/// Initialise the platform logger. Call once at app startup.
pub fn init_logger() {
    #[cfg(target_os = "android")]
    {
        android_logger::init_once(
            android_logger::Config::default()
                .with_max_level(log::LevelFilter::Debug)
                .with_tag(TAG),
        );
    }

    // iOS / desktop: nothing to initialise – we write directly to stderr.
}

// ── public macros ────────────────────────────────────────────────────────────

/// Log an error-level message.
#[macro_export]
macro_rules! mls_error {
    ($($arg:tt)*) => {
        $crate::logger::_log($crate::logger::Level::Error, &format!($($arg)*));
    };
}

/// Log a warning-level message.
#[macro_export]
macro_rules! mls_warn {
    ($($arg:tt)*) => {
        $crate::logger::_log($crate::logger::Level::Warn, &format!($($arg)*));
    };
}

/// Log an info-level message.
#[macro_export]
macro_rules! mls_info {
    ($($arg:tt)*) => {
        $crate::logger::_log($crate::logger::Level::Info, &format!($($arg)*));
    };
}

/// Log a debug-level message.
#[macro_export]
macro_rules! mls_debug {
    ($($arg:tt)*) => {
        $crate::logger::_log($crate::logger::Level::Debug, &format!($($arg)*));
    };
}

// ── internal impl (do not use directly) ──────────────────────────────────────

#[doc(hidden)]
#[derive(Clone, Copy)]
pub enum Level {
    Error,
    Warn,
    Info,
    Debug,
}

#[doc(hidden)]
#[inline]
pub fn _log(level: Level, msg: &str) {
    #[cfg(target_os = "android")]
    {
        match level {
            Level::Error => log::error!("[{}] {}", TAG, msg),
            Level::Warn  => log::warn!("[{}] {}", TAG, msg),
            Level::Info  => log::info!("[{}] {}", TAG, msg),
            Level::Debug => log::debug!("[{}] {}", TAG, msg),
        }
    }

    #[cfg(not(target_os = "android"))]
    {
        let label = match level {
            Level::Error => "ERROR",
            Level::Warn  => "WARN",
            Level::Info  => "INFO",
            Level::Debug => "DEBUG",
        };
        eprintln!("[{}] [{}] {}", TAG, label, msg);
    }
}
