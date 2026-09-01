/// Controls how the scanner reacts to malformed or unsupported escape
/// sequences.
///
/// The default is [`Mode::Strict`]: anything that does not fully conform to
/// the escape sequence grammar is reported as an error and the caller
/// decides what to do with it. This matters because escape sequences are one
/// of the few ways untrusted text (log lines, chat messages, file contents
/// piped through `cat`) can make a terminal do something the reader did not
/// expect. Failing closed by default means a caller has to opt in before
/// silently accepting whatever a byte stream throws at it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    /// Reject malformed, oversized, or unsupported escape sequences.
    Strict,
    /// Recover from the same conditions the way most real terminals do:
    /// skip what cannot be parsed and keep going instead of erroring out.
    Lenient,
}

impl Default for Mode {
    fn default() -> Self {
        Mode::Strict
    }
}
