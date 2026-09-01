//! Scans byte streams for ANSI/VT terminal escape sequences.
//!
//! The entry point is [`EscapeScanner`], an iterator over [`Event`]s that
//! separates plain text from escape sequences. Behavior on malformed input
//! is controlled by [`Mode`]: [`Mode::Strict`] (the default) reports an
//! error instead of guessing, [`Mode::Lenient`] recovers the way a real
//! terminal would.

mod error;
mod mode;
mod scanner;

pub use error::ScanError;
pub use mode::Mode;
pub use scanner::{EscapeScanner, Event};
