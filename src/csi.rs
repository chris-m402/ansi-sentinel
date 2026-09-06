//! Typed parameter parsing for CSI (`ESC [ ... final`) sequences.
//!
//! [`EscapeScanner`](crate::EscapeScanner) hands back a CSI sequence as raw
//! bytes because scanning has to succeed or fail before anyone cares what
//! the numbers inside mean. Once a caller has a complete sequence and wants
//! to act on it (is this an SGR reset? a cursor move by how many rows?) it
//! needs the parameter fields as integers instead of ASCII digits.

/// One parameter field of a CSI sequence.
///
/// A field can be omitted (`ESC[;1m` has an empty first field, `ESC[1;m`
/// an empty second one), which every terminal treats as "use the default
/// for this position" rather than as zero. `None` represents that case;
/// `Some(n)` is a field that was present and parsed as `n`.
pub type CsiParam = Option<u32>;

/// Parses the parameter fields out of a complete CSI sequence.
///
/// `sequence` must be exactly what [`Event::Escape`](crate::Event::Escape)
/// produces for a CSI sequence: a leading `ESC [`, zero or more parameter
/// and intermediate bytes, and a single final byte. Anything else -
/// including a sequence that is not CSI at all - returns `None`.
///
/// Parameter fields are split on `;`. This function only handles the plain
/// numeric form; a sequence that uses a private-marker prefix (`ESC[?25h`)
/// or colon-separated sub-parameters (`ESC[38:2:255:0:0m`) returns `None`
/// rather than guessing at a meaning for those bytes, since both are
/// extensions with sequence-specific rules that a generic parser can't
/// interpret correctly. Callers that need those should match on the raw
/// bytes themselves.
///
/// A field whose value would overflow `u32` also returns `None` for the
/// whole sequence: the scanner's own `MAX_PARAM_LEN` limit means this can't
/// happen for sequences it accepted in strict mode, but a caller re-parsing
/// bytes obtained some other way (lenient mode, a stored log line) should
/// get a clear "can't parse this" instead of a silently wrong number.
///
/// ```
/// use ansi_sentinel::csi::parse_csi_params;
///
/// assert_eq!(parse_csi_params(b"\x1b[31m"), Some(vec![Some(31)]));
/// assert_eq!(parse_csi_params(b"\x1b[1;;3m"), Some(vec![Some(1), None, Some(3)]));
/// assert_eq!(parse_csi_params(b"\x1b[m"), Some(vec![]));
/// assert_eq!(parse_csi_params(b"\x1b[?25h"), None);
/// ```
pub fn parse_csi_params(sequence: &[u8]) -> Option<Vec<CsiParam>> {
    let rest = sequence.strip_prefix(b"\x1b[")?;
    let (&final_byte, body) = rest.split_last()?;
    if !(0x40..=0x7E).contains(&final_byte) {
        return None;
    }

    // Parameter bytes (0x30..=0x3F) come first, then intermediate bytes
    // (0x20..=0x2F); stop at the first intermediate byte so those aren't
    // fed into the number parser below.
    let param_end = body
        .iter()
        .position(|&b| (0x20..=0x2F).contains(&b))
        .unwrap_or(body.len());
    let param_bytes = &body[..param_end];

    if param_bytes.is_empty() {
        return Some(Vec::new());
    }

    let mut fields = Vec::new();
    for field in param_bytes.split(|&b| b == b';') {
        if field.is_empty() {
            fields.push(None);
            continue;
        }
        let mut value: u32 = 0;
        for &b in field {
            if !b.is_ascii_digit() {
                return None;
            }
            let digit = (b - b'0') as u32;
            value = value.checked_mul(10)?.checked_add(digit)?;
        }
        fields.push(Some(value));
    }
    Some(fields)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn single_param() {
        assert_eq!(parse_csi_params(b"\x1b[31m"), Some(vec![Some(31)]));
    }

    #[test]
    fn no_params_defaults_to_empty_list() {
        assert_eq!(parse_csi_params(b"\x1b[m"), Some(vec![]));
    }

    #[test]
    fn multiple_params() {
        assert_eq!(
            parse_csi_params(b"\x1b[1;30;47m"),
            Some(vec![Some(1), Some(30), Some(47)])
        );
    }

    #[test]
    fn empty_fields_are_none() {
        assert_eq!(
            parse_csi_params(b"\x1b[1;;3m"),
            Some(vec![Some(1), None, Some(3)])
        );
        assert_eq!(parse_csi_params(b"\x1b[;1m"), Some(vec![None, Some(1)]));
        assert_eq!(parse_csi_params(b"\x1b[1;m"), Some(vec![Some(1), None]));
    }

    #[test]
    fn intermediate_bytes_are_excluded_from_params() {
        // ESC [ 1 SP q  -- DECSCUSR, cursor style, with an intermediate byte.
        assert_eq!(parse_csi_params(b"\x1b[1 q"), Some(vec![Some(1)]));
    }

    #[test]
    fn private_marker_prefix_is_not_numeric() {
        assert_eq!(parse_csi_params(b"\x1b[?25h"), None);
    }

    #[test]
    fn colon_sub_parameters_are_not_numeric() {
        assert_eq!(parse_csi_params(b"\x1b[38:2:255:0:0m"), None);
    }

    #[test]
    fn non_csi_input_is_rejected() {
        assert_eq!(parse_csi_params(b"\x1bc"), None);
        assert_eq!(parse_csi_params(b"not an escape"), None);
        assert_eq!(parse_csi_params(b"\x1b["), None);
    }

    #[test]
    fn overflowing_param_is_rejected() {
        assert_eq!(parse_csi_params(b"\x1b[99999999999999m"), None);
    }
}
