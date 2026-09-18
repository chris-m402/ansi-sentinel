//! Semantic interpretation of SGR (`ESC [ ... m`) sequences.
//!
//! [`parse_csi_params`](crate::parse_csi_params) turns a CSI sequence into
//! integer fields but doesn't know what those integers mean; the meaning is
//! specific to which final byte the sequence ends in. This module covers the
//! one final byte almost every terminal-writing program cares about: `m`,
//! Select Graphic Rendition, which sets colors and text attributes.

use crate::csi::{parse_csi_params, CsiParam};

/// A color selected by an SGR foreground/background attribute.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Color {
    /// One of the eight standard colors (0 = black .. 7 = white), set by
    /// `30..=37` or `40..=47`.
    Named(u8),
    /// One of the eight bright colors, set by the non-standard but
    /// near-universal `90..=97` / `100..=107` range.
    BrightNamed(u8),
    /// A 256-color palette index, set by `38;5;n` or `48;5;n`.
    Indexed(u8),
    /// A 24-bit color, set by `38;2;r;g;b` or `48;2;r;g;b`.
    Rgb(u8, u8, u8),
}

/// One effect of an SGR sequence, in the order its parameter appeared.
///
/// A single sequence can carry several of these: `ESC[1;31m` is
/// `[Bold, Foreground(Named(1))]`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SgrAttribute {
    /// `0` (or no parameters at all): clear every attribute set so far.
    Reset,
    Bold,
    Faint,
    Italic,
    Underline,
    SlowBlink,
    RapidBlink,
    Reverse,
    Conceal,
    Strikethrough,
    /// `22`: cancels both [`Bold`](Self::Bold) and [`Faint`](Self::Faint).
    NormalIntensity,
    NoItalic,
    NoUnderline,
    NoBlink,
    NoReverse,
    Reveal,
    NoStrikethrough,
    Foreground(Color),
    Background(Color),
    DefaultForeground,
    DefaultBackground,
}

/// Parses a complete SGR sequence into the attributes it sets, in order.
///
/// `sequence` must be exactly what [`Event::Escape`](crate::Event::Escape)
/// produces for an SGR sequence: a leading `ESC [`, parameter bytes, and a
/// final `m`. Anything else, including a CSI sequence with a different final
/// byte, returns `None`.
///
/// A sequence with no parameters (`ESC[m`) is equivalent to `ESC[0m` and
/// parses as `[Reset]`, matching how every terminal treats it.
///
/// Parameter codes this function doesn't recognize, and extended color
/// selectors (`38`/`48`) with a malformed or incomplete argument, cause the
/// whole sequence to return `None` rather than silently dropping the
/// attribute a caller asked about. This mirrors [`parse_csi_params`]'s
/// stance of refusing to guess.
///
/// ```
/// use ansi_sentinel::sgr::{parse_sgr, Color, SgrAttribute};
///
/// assert_eq!(parse_sgr(b"\x1b[31m"), Some(vec![SgrAttribute::Foreground(Color::Named(1))]));
/// assert_eq!(parse_sgr(b"\x1b[m"), Some(vec![SgrAttribute::Reset]));
/// assert_eq!(
///     parse_sgr(b"\x1b[38;2;255;0;0m"),
///     Some(vec![SgrAttribute::Foreground(Color::Rgb(255, 0, 0))]),
/// );
/// ```
pub fn parse_sgr(sequence: &[u8]) -> Option<Vec<SgrAttribute>> {
    if sequence.last() != Some(&b'm') {
        return None;
    }
    let params = parse_csi_params(sequence)?;
    if params.is_empty() {
        return Some(vec![SgrAttribute::Reset]);
    }

    let mut attrs = Vec::with_capacity(params.len());
    let mut i = 0;
    while i < params.len() {
        let code = params[i].unwrap_or(0);
        let step = match code {
            0 => {
                attrs.push(SgrAttribute::Reset);
                1
            }
            1 => {
                attrs.push(SgrAttribute::Bold);
                1
            }
            2 => {
                attrs.push(SgrAttribute::Faint);
                1
            }
            3 => {
                attrs.push(SgrAttribute::Italic);
                1
            }
            4 => {
                attrs.push(SgrAttribute::Underline);
                1
            }
            5 => {
                attrs.push(SgrAttribute::SlowBlink);
                1
            }
            6 => {
                attrs.push(SgrAttribute::RapidBlink);
                1
            }
            7 => {
                attrs.push(SgrAttribute::Reverse);
                1
            }
            8 => {
                attrs.push(SgrAttribute::Conceal);
                1
            }
            9 => {
                attrs.push(SgrAttribute::Strikethrough);
                1
            }
            22 => {
                attrs.push(SgrAttribute::NormalIntensity);
                1
            }
            23 => {
                attrs.push(SgrAttribute::NoItalic);
                1
            }
            24 => {
                attrs.push(SgrAttribute::NoUnderline);
                1
            }
            25 => {
                attrs.push(SgrAttribute::NoBlink);
                1
            }
            27 => {
                attrs.push(SgrAttribute::NoReverse);
                1
            }
            28 => {
                attrs.push(SgrAttribute::Reveal);
                1
            }
            29 => {
                attrs.push(SgrAttribute::NoStrikethrough);
                1
            }
            30..=37 => {
                attrs.push(SgrAttribute::Foreground(Color::Named((code - 30) as u8)));
                1
            }
            38 => {
                let (color, consumed) = parse_extended_color(&params[i + 1..])?;
                attrs.push(SgrAttribute::Foreground(color));
                1 + consumed
            }
            39 => {
                attrs.push(SgrAttribute::DefaultForeground);
                1
            }
            40..=47 => {
                attrs.push(SgrAttribute::Background(Color::Named((code - 40) as u8)));
                1
            }
            48 => {
                let (color, consumed) = parse_extended_color(&params[i + 1..])?;
                attrs.push(SgrAttribute::Background(color));
                1 + consumed
            }
            49 => {
                attrs.push(SgrAttribute::DefaultBackground);
                1
            }
            90..=97 => {
                attrs.push(SgrAttribute::Foreground(Color::BrightNamed((code - 90) as u8)));
                1
            }
            100..=107 => {
                attrs.push(SgrAttribute::Background(Color::BrightNamed((code - 100) as u8)));
                1
            }
            _ => return None,
        };
        i += step;
    }
    Some(attrs)
}

/// `rest` is everything after a `38` or `48` field. Returns the color it
/// selects and how many of `rest`'s fields were consumed to build it (not
/// counting the `38`/`48` field itself).
fn parse_extended_color(rest: &[CsiParam]) -> Option<(Color, usize)> {
    match field(rest, 0)? {
        5 => {
            let index = u8::try_from(field(rest, 1)?).ok()?;
            Some((Color::Indexed(index), 2))
        }
        2 => {
            let r = u8::try_from(field(rest, 1)?).ok()?;
            let g = u8::try_from(field(rest, 2)?).ok()?;
            let b = u8::try_from(field(rest, 3)?).ok()?;
            Some((Color::Rgb(r, g, b), 4))
        }
        _ => None,
    }
}

fn field(params: &[CsiParam], index: usize) -> Option<u32> {
    params.get(index).copied().flatten()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn no_params_is_reset() {
        assert_eq!(parse_sgr(b"\x1b[m"), Some(vec![SgrAttribute::Reset]));
    }

    #[test]
    fn explicit_zero_is_reset() {
        assert_eq!(parse_sgr(b"\x1b[0m"), Some(vec![SgrAttribute::Reset]));
    }

    #[test]
    fn single_style_attribute() {
        assert_eq!(parse_sgr(b"\x1b[1m"), Some(vec![SgrAttribute::Bold]));
    }

    #[test]
    fn combined_bold_and_foreground() {
        assert_eq!(
            parse_sgr(b"\x1b[1;31m"),
            Some(vec![SgrAttribute::Bold, SgrAttribute::Foreground(Color::Named(1))])
        );
    }

    #[test]
    fn named_background() {
        assert_eq!(
            parse_sgr(b"\x1b[44m"),
            Some(vec![SgrAttribute::Background(Color::Named(4))])
        );
    }

    #[test]
    fn bright_foreground_and_background() {
        assert_eq!(
            parse_sgr(b"\x1b[92;100m"),
            Some(vec![
                SgrAttribute::Foreground(Color::BrightNamed(2)),
                SgrAttribute::Background(Color::BrightNamed(0)),
            ])
        );
    }

    #[test]
    fn indexed_foreground() {
        assert_eq!(
            parse_sgr(b"\x1b[38;5;196m"),
            Some(vec![SgrAttribute::Foreground(Color::Indexed(196))])
        );
    }

    #[test]
    fn rgb_background() {
        assert_eq!(
            parse_sgr(b"\x1b[48;2;10;20;30m"),
            Some(vec![SgrAttribute::Background(Color::Rgb(10, 20, 30))])
        );
    }

    #[test]
    fn extended_color_followed_by_more_attributes() {
        assert_eq!(
            parse_sgr(b"\x1b[38;5;196;1m"),
            Some(vec![
                SgrAttribute::Foreground(Color::Indexed(196)),
                SgrAttribute::Bold,
            ])
        );
    }

    #[test]
    fn default_colors() {
        assert_eq!(
            parse_sgr(b"\x1b[39;49m"),
            Some(vec![SgrAttribute::DefaultForeground, SgrAttribute::DefaultBackground])
        );
    }

    #[test]
    fn truncated_extended_color_is_rejected() {
        assert_eq!(parse_sgr(b"\x1b[38;5m"), None);
        assert_eq!(parse_sgr(b"\x1b[38;2;255;0m"), None);
    }

    #[test]
    fn unknown_color_space_selector_is_rejected() {
        assert_eq!(parse_sgr(b"\x1b[38;9;1m"), None);
    }

    #[test]
    fn unrecognized_code_is_rejected() {
        // 10..=20 select alternate fonts; not worth guessing at.
        assert_eq!(parse_sgr(b"\x1b[11m"), None);
    }

    #[test]
    fn non_sgr_final_byte_is_rejected() {
        assert_eq!(parse_sgr(b"\x1b[31A"), None);
    }

    #[test]
    fn colon_sub_parameters_are_rejected() {
        // Common in truecolor output from some emitters; not the plain
        // `;`-separated form this parser handles.
        assert_eq!(parse_sgr(b"\x1b[38:2:255:0:0m"), None);
    }
}
