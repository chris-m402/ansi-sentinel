use std::fmt;

/// A problem found while scanning an escape sequence in [`Mode::Strict`](crate::Mode::Strict).
///
/// Every variant carries the byte offset of the `ESC` (0x1B) that started
/// the offending sequence, so a caller can slice the original input to
/// inspect or log the exact bytes involved.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScanError {
    /// Input ended before the sequence reached a final byte.
    UnterminatedSequence { start: usize },
    /// A byte appeared that is not valid anywhere in the sequence, or
    /// appeared in the wrong position (for example a parameter byte after
    /// an intermediate byte).
    DisallowedByte { start: usize, byte: u8 },
    /// The sequence had more parameters than `MAX_PARAMS` allows.
    TooManyParameters { start: usize },
    /// A single parameter had more digits than `MAX_PARAM_LEN` allows.
    ParameterTooLarge { start: usize },
    /// The sequence is a recognized introducer (OSC, DCS, SOS, PM, or APC)
    /// for a string-terminated control sequence, which this scanner does
    /// not parse yet.
    UnsupportedSequence { start: usize, byte: u8 },
}

impl ScanError {
    /// Byte offset, in the original input, of the `ESC` that started the
    /// sequence this error refers to.
    pub fn start(&self) -> usize {
        match *self {
            ScanError::UnterminatedSequence { start } => start,
            ScanError::DisallowedByte { start, .. } => start,
            ScanError::TooManyParameters { start } => start,
            ScanError::ParameterTooLarge { start } => start,
            ScanError::UnsupportedSequence { start, .. } => start,
        }
    }
}

impl fmt::Display for ScanError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            ScanError::UnterminatedSequence { start } => {
                write!(f, "unterminated escape sequence starting at byte {start}")
            }
            ScanError::DisallowedByte { start, byte } => {
                write!(
                    f,
                    "disallowed byte 0x{byte:02X} in escape sequence starting at byte {start}"
                )
            }
            ScanError::TooManyParameters { start } => {
                write!(
                    f,
                    "too many parameters in escape sequence starting at byte {start}"
                )
            }
            ScanError::ParameterTooLarge { start } => {
                write!(
                    f,
                    "parameter too long in escape sequence starting at byte {start}"
                )
            }
            ScanError::UnsupportedSequence { start, byte } => {
                write!(
                    f,
                    "unsupported string sequence (introducer 0x{byte:02X}) starting at byte {start}"
                )
            }
        }
    }
}

impl std::error::Error for ScanError {}
