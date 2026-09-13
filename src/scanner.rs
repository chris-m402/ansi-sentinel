use crate::error::ScanError;
use crate::mode::Mode;

const ESC: u8 = 0x1B;
const BEL: u8 = 0x07;
const OSC: u8 = b']';
const DCS: u8 = b'P';
const SOS: u8 = b'X';
const PM: u8 = b'^';
const APC: u8 = b'_';

/// Far more parameters than any real control sequence uses. Anything past
/// this is either a bug in the sender or an attempt to make a naive parser
/// do a lot of work, so strict mode rejects it rather than allocating for it.
const MAX_PARAMS: usize = 32;

/// Same reasoning as `MAX_PARAMS`, applied to the digit count of a single
/// parameter field.
const MAX_PARAM_LEN: usize = 8;

/// One piece of a scanned byte stream.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Event<'a> {
    /// A run of bytes with no escape sequences in it.
    Text(&'a [u8]),
    /// A complete, well-formed escape sequence, including its leading `ESC`.
    Escape(&'a [u8]),
    /// In [`Mode::Lenient`] only: bytes that looked like the start of an
    /// escape sequence but turned out malformed, oversized, or unterminated.
    /// Skipped rather than surfaced as text so callers don't accidentally
    /// render control bytes.
    Invalid(&'a [u8]),
}

enum Outcome {
    Complete,
    Unterminated,
    Disallowed(u8),
    TooManyParams,
    ParamTooLong,
}

/// Scans a byte slice into a sequence of [`Event`]s.
///
/// ```
/// use ansi_sentinel::{EscapeScanner, Event};
///
/// let input = b"hello \x1b[31mworld\x1b[0m";
/// let events: Vec<_> = EscapeScanner::strict(input).collect();
/// assert!(events[0].is_ok());
/// ```
pub struct EscapeScanner<'a> {
    input: &'a [u8],
    pos: usize,
    mode: Mode,
}

impl<'a> EscapeScanner<'a> {
    pub fn new(input: &'a [u8], mode: Mode) -> Self {
        EscapeScanner { input, pos: 0, mode }
    }

    /// Shorthand for `EscapeScanner::new(input, Mode::Strict)`.
    pub fn strict(input: &'a [u8]) -> Self {
        EscapeScanner::new(input, Mode::Strict)
    }

    /// Shorthand for `EscapeScanner::new(input, Mode::Lenient)`.
    pub fn lenient(input: &'a [u8]) -> Self {
        EscapeScanner::new(input, Mode::Lenient)
    }

    fn finish(&self, start: usize, end: usize, outcome: Outcome) -> Result<Event<'a>, ScanError> {
        let lenient = self.mode == Mode::Lenient;
        match outcome {
            Outcome::Complete => Ok(Event::Escape(&self.input[start..end])),
            Outcome::TooManyParams if lenient => Ok(Event::Escape(&self.input[start..end])),
            Outcome::TooManyParams => Err(ScanError::TooManyParameters { start }),
            Outcome::ParamTooLong if lenient => Ok(Event::Escape(&self.input[start..end])),
            Outcome::ParamTooLong => Err(ScanError::ParameterTooLarge { start }),
            Outcome::Disallowed(_) if lenient => Ok(Event::Invalid(&self.input[start..end])),
            Outcome::Disallowed(byte) => Err(ScanError::DisallowedByte { start, byte }),
            Outcome::Unterminated if lenient => Ok(Event::Invalid(&self.input[start..end])),
            Outcome::Unterminated => Err(ScanError::UnterminatedSequence { start }),
        }
    }

    /// `self.input[start]` must be `ESC`. Returns the exclusive end offset
    /// of whatever was recognized (complete or not) and what it was.
    fn scan_escape(&self, start: usize) -> (usize, Outcome) {
        let bytes = self.input;
        let len = bytes.len();
        let mut i = start + 1;
        if i >= len {
            return (i, Outcome::Unterminated);
        }
        match bytes[i] {
            b'[' => self.scan_csi(i + 1),
            OSC | DCS | SOS | PM | APC => self.scan_control_string(bytes[i], i + 1),
            0x40..=0x7E => (i + 1, Outcome::Complete),
            0x20..=0x2F => {
                i += 1;
                while i < len && (0x20..=0x2F).contains(&bytes[i]) {
                    i += 1;
                }
                if i >= len {
                    (i, Outcome::Unterminated)
                } else if (0x30..=0x7E).contains(&bytes[i]) {
                    (i + 1, Outcome::Complete)
                } else {
                    (i, Outcome::Disallowed(bytes[i]))
                }
            }
            b => (i, Outcome::Disallowed(b)),
        }
    }

    /// `params_start` points just past `ESC [`.
    fn scan_csi(&self, params_start: usize) -> (usize, Outcome) {
        let bytes = self.input;
        let len = bytes.len();
        let mut i = params_start;
        let mut param_count: usize = 0;
        let mut current_len: usize = 0;
        let mut seen_param_byte = false;
        let mut seen_intermediate = false;
        let mut violation: Option<Outcome> = None;

        while i < len {
            match bytes[i] {
                b @ 0x30..=0x3F => {
                    if seen_intermediate && violation.is_none() {
                        violation = Some(Outcome::Disallowed(b));
                    }
                    if b == b';' {
                        param_count += 1;
                        current_len = 0;
                    } else {
                        seen_param_byte = true;
                        current_len += 1;
                        if current_len > MAX_PARAM_LEN && violation.is_none() {
                            violation = Some(Outcome::ParamTooLong);
                        }
                    }
                    i += 1;
                }
                0x20..=0x2F => {
                    seen_intermediate = true;
                    i += 1;
                }
                0x40..=0x7E => {
                    if seen_param_byte || current_len > 0 {
                        param_count += 1;
                    }
                    if param_count > MAX_PARAMS && violation.is_none() {
                        violation = Some(Outcome::TooManyParams);
                    }
                    return (i + 1, violation.unwrap_or(Outcome::Complete));
                }
                b => return (i, violation.unwrap_or(Outcome::Disallowed(b))),
            }
        }
        (i, violation.unwrap_or(Outcome::Unterminated))
    }

    /// `content_start` points just past the introducer byte of an
    /// OSC/DCS/SOS/PM/APC sequence. Scans its string body up to the
    /// terminator.
    ///
    /// Every one of these introducers accepts the two-byte string
    /// terminator `ST` (`ESC \`). OSC additionally accepts a bare `BEL`,
    /// which is not in ECMA-48 but is how xterm has terminated OSC since
    /// before ST was common and is what most real-world senders still use
    /// for things like window-title updates. DCS/SOS/PM/APC get no such
    /// exception: a `BEL` inside one of those is just a disallowed control
    /// byte.
    ///
    /// Body bytes are otherwise restricted to the printable range
    /// (0x20..=0x7E). That excludes a raw `ESC` not immediately followed by
    /// `\`, which would otherwise let an unterminated string silently
    /// swallow whatever comes after it, including sequences a caller needs
    /// to see.
    fn scan_control_string(&self, introducer: u8, content_start: usize) -> (usize, Outcome) {
        let bytes = self.input;
        let len = bytes.len();
        let mut j = content_start;
        while j < len {
            match bytes[j] {
                BEL if introducer == OSC => return (j + 1, Outcome::Complete),
                ESC => {
                    return if j + 1 >= len {
                        (j, Outcome::Unterminated)
                    } else if bytes[j + 1] == b'\\' {
                        (j + 2, Outcome::Complete)
                    } else {
                        (j, Outcome::Disallowed(ESC))
                    };
                }
                0x20..=0x7E => j += 1,
                b => return (j, Outcome::Disallowed(b)),
            }
        }
        (j, Outcome::Unterminated)
    }
}

impl<'a> Iterator for EscapeScanner<'a> {
    type Item = Result<Event<'a>, ScanError>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.pos >= self.input.len() {
            return None;
        }
        if self.input[self.pos] == ESC {
            let start = self.pos;
            let (end, outcome) = self.scan_escape(start);
            self.pos = end;
            return Some(self.finish(start, end, outcome));
        }
        let start = self.pos;
        while self.pos < self.input.len() && self.input[self.pos] != ESC {
            self.pos += 1;
        }
        Some(Ok(Event::Text(&self.input[start..self.pos])))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn events(input: &[u8], mode: Mode) -> Vec<Result<Event<'_>, ScanError>> {
        EscapeScanner::new(input, mode).collect()
    }

    #[test]
    fn plain_text_has_no_escapes() {
        let got = events(b"hello world", Mode::Strict);
        assert_eq!(got, vec![Ok(Event::Text(b"hello world"))]);
    }

    #[test]
    fn well_formed_csi_is_accepted_in_both_modes() {
        let input = b"\x1b[31m";
        assert_eq!(
            events(input, Mode::Strict),
            vec![Ok(Event::Escape(b"\x1b[31m"))]
        );
        assert_eq!(
            events(input, Mode::Lenient),
            vec![Ok(Event::Escape(b"\x1b[31m"))]
        );
    }

    #[test]
    fn text_and_escape_and_text() {
        let input = b"a\x1b[1mb";
        let got = events(input, Mode::Strict);
        assert_eq!(
            got,
            vec![
                Ok(Event::Text(b"a")),
                Ok(Event::Escape(b"\x1b[1m")),
                Ok(Event::Text(b"b")),
            ]
        );
    }

    #[test]
    fn unterminated_sequence_errors_in_strict_mode() {
        let input = b"\x1b[31";
        let got = events(input, Mode::Strict);
        assert_eq!(got, vec![Err(ScanError::UnterminatedSequence { start: 0 })]);
    }

    #[test]
    fn unterminated_sequence_recovers_in_lenient_mode() {
        let input = b"\x1b[31";
        let got = events(input, Mode::Lenient);
        assert_eq!(got, vec![Ok(Event::Invalid(b"\x1b[31"))]);
    }

    #[test]
    fn disallowed_byte_inside_csi_errors_in_strict_mode() {
        // 0x01 is a control byte, not valid inside a CSI sequence.
        let input = b"\x1b[3\x01m";
        let got = events(input, Mode::Strict);
        assert_eq!(
            got,
            vec![Err(ScanError::DisallowedByte { start: 0, byte: 0x01 })]
        );
    }

    #[test]
    fn simple_two_byte_escape_is_complete() {
        let input = b"\x1bc"; // RIS, full reset
        let got = events(input, Mode::Strict);
        assert_eq!(got, vec![Ok(Event::Escape(b"\x1bc"))]);
    }

    #[test]
    fn osc_terminated_by_bel_is_accepted() {
        let input = b"\x1b]0;title\x07after";
        let got = events(input, Mode::Strict);
        assert_eq!(
            got,
            vec![
                Ok(Event::Escape(b"\x1b]0;title\x07")),
                Ok(Event::Text(b"after")),
            ]
        );
    }

    #[test]
    fn osc_terminated_by_st_is_accepted() {
        let input = b"\x1b]0;title\x1b\\after";
        let got = events(input, Mode::Strict);
        assert_eq!(
            got,
            vec![
                Ok(Event::Escape(b"\x1b]0;title\x1b\\")),
                Ok(Event::Text(b"after")),
            ]
        );
    }

    #[test]
    fn dcs_requires_st_and_rejects_bel() {
        // DCS (ESC P) has no BEL exception, unlike OSC: BEL is just a
        // disallowed byte inside its string.
        let input = b"\x1bP1$q\x07";
        let got = events(input, Mode::Strict);
        assert_eq!(
            got,
            vec![Err(ScanError::DisallowedByte { start: 0, byte: BEL })]
        );
    }

    #[test]
    fn dcs_terminated_by_st_is_accepted() {
        let input = b"\x1bP1$q\x1b\\";
        let got = events(input, Mode::Strict);
        assert_eq!(got, vec![Ok(Event::Escape(b"\x1bP1$q\x1b\\"))]);
    }

    #[test]
    fn sos_pm_apc_are_accepted() {
        assert_eq!(
            events(b"\x1bXdata\x1b\\", Mode::Strict),
            vec![Ok(Event::Escape(b"\x1bXdata\x1b\\"))]
        );
        assert_eq!(
            events(b"\x1b^data\x1b\\", Mode::Strict),
            vec![Ok(Event::Escape(b"\x1b^data\x1b\\"))]
        );
        assert_eq!(
            events(b"\x1b_data\x1b\\", Mode::Strict),
            vec![Ok(Event::Escape(b"\x1b_data\x1b\\"))]
        );
    }

    #[test]
    fn unterminated_control_string_errors_in_strict_mode() {
        let input = b"\x1b]0;title";
        let got = events(input, Mode::Strict);
        assert_eq!(got, vec![Err(ScanError::UnterminatedSequence { start: 0 })]);
    }

    #[test]
    fn unterminated_control_string_recovers_in_lenient_mode() {
        let input = b"\x1b]0;title";
        let got = events(input, Mode::Lenient);
        assert_eq!(got, vec![Ok(Event::Invalid(b"\x1b]0;title"))]);
    }

    #[test]
    fn embedded_esc_aborts_control_string_and_resumes_parsing() {
        // The OSC string is never terminated; the ESC that starts the CSI
        // sequence is left for the next call to `next` instead of being
        // swallowed as string content.
        let input = b"\x1b]0;title\x1b[31m";
        let got = events(input, Mode::Lenient);
        assert_eq!(
            got,
            vec![
                Ok(Event::Invalid(b"\x1b]0;title")),
                Ok(Event::Escape(b"\x1b[31m")),
            ]
        );
    }

    #[test]
    fn control_byte_inside_control_string_errors_in_strict_mode() {
        let input = b"\x1b]0;ti\x01tle\x07";
        let got = events(input, Mode::Strict);
        assert_eq!(
            got,
            vec![Err(ScanError::DisallowedByte { start: 0, byte: 0x01 })]
        );
    }

    #[test]
    fn too_many_parameters_errors_in_strict_mode() {
        let params = "1;".repeat(MAX_PARAMS + 1);
        let input = format!("\x1b[{params}m");
        let got = events(input.as_bytes(), Mode::Strict);
        assert_eq!(got, vec![Err(ScanError::TooManyParameters { start: 0 })]);
    }
}
