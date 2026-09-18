# ansi-sentinel

A Rust library for scanning ANSI/VT terminal escape sequences out of a byte
stream.

## Why

Escape sequences are how a terminal is told to change color, move the
cursor, rename the window, or reset itself. That's fine when the terminal
program itself is generating them. It's a different story when the bytes
come from somewhere you don't control: a log file, a `git commit` message, a
chat client, a file someone asked you to `cat`. A crafted sequence in that
input can rewrite the visible prompt, hide text, or otherwise mislead
whoever is looking at the terminal. Most terminal emulators handle malformed
escape sequences by guessing and moving on, which is the right thing for a
terminal to do and the wrong thing for code that first wants to decide
whether input is trustworthy.

This library scans a byte slice and hands back each piece as plain text or
as a recognized escape sequence, and it is strict by default: anything that
doesn't fully match the escape sequence grammar is an error, not a guess.
Callers that actually want terminal-like tolerance can ask for it
explicitly.

## Usage

```rust
use ansi_sentinel::{EscapeScanner, Event, Mode};

let input = b"hello \x1b[31mworld\x1b[0m\n";

// Strict: stop at the first thing that isn't a fully valid sequence.
for event in EscapeScanner::strict(input) {
    match event {
        Ok(Event::Text(bytes)) => print!("{}", String::from_utf8_lossy(bytes)),
        Ok(Event::Escape(bytes)) => println!("<escape: {bytes:?}>"),
        Ok(Event::Invalid(_)) => unreachable!("strict mode never emits Invalid"),
        Err(e) => {
            eprintln!("rejecting input: {e}");
            break;
        }
    }
}

// Lenient: never error, best-effort recovery like a real terminal.
let events: Vec<_> = EscapeScanner::new(input, Mode::Lenient).collect();
assert!(events.iter().all(|e| e.is_ok()));
```

## Strict vs. lenient

- **Strict** (default): unterminated sequences, unexpected bytes inside a
  sequence, too many parameters, or an oversized parameter all produce a
  `ScanError` that names the byte offset of the sequence. Use this when you
  are deciding whether to trust or display input you did not generate
  yourself, and would rather reject the whole thing than render half of a
  malformed sequence.
- **Lenient**: the same conditions never produce an error. Well-formed
  sequences are still returned as `Event::Escape`; anything that couldn't be
  parsed becomes `Event::Invalid` and scanning continues right after it.
  Use this when you're processing output from a program you already trust
  and want behavior closer to a real terminal.

## Status

Early. The scanner recognizes CSI sequences (`ESC [ ... final byte`), the
two-byte `Fe` escapes (`ESC` + one final byte, e.g. `ESC c`),
intermediate-plus-final `nF` escapes (e.g. `ESC ( B`), and the
string-terminated OSC/DCS/SOS/PM/APC sequences. Those string sequences must
end in `ST` (`ESC \`); OSC additionally accepts a bare `BEL`, matching what
xterm and most real senders use for things like window-title updates. A
stray control byte or unescaped `ESC` inside one of those strings ends it as
malformed rather than being absorbed as content.

Once you have a CSI `Event::Escape`, `csi::parse_csi_params` turns its
parameter fields into `Vec<Option<u32>>` (`None` for an omitted field, so
`ESC[1;;3m` parses as `[Some(1), None, Some(3)]`). It only handles the plain
`;`-separated numeric form; private-marker sequences like `ESC[?25h` and
colon sub-parameters like `ESC[38:2:255:0:0m` return `None` since a generic
parser can't assign them a meaning.

`sgr::parse_sgr` builds on that for the one CSI final byte almost every
color-producing program cares about: `m`, Select Graphic Rendition. It turns
a sequence like `ESC[1;38;5;196m` into `[Bold, Foreground(Indexed(196))]`,
covering the standard and bright named colors, 256-color indices, and 24-bit
RGB. Like the rest of this library it fails closed: a code it doesn't
recognize, or an extended color selector with a missing argument, makes the
whole sequence return `None` instead of dropping the attribute silently.

## License

MIT, see [LICENSE](LICENSE).
