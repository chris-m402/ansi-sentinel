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
  sequence, too many parameters, an oversized parameter, or a sequence type
  this scanner doesn't parse yet (OSC/DCS/SOS/PM/APC strings) all produce a
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
two-byte `Fe` escapes (`ESC` + one final byte, e.g. `ESC c`), and
intermediate-plus-final `nF` escapes (e.g. `ESC ( B`). It does not yet parse
the contents of OSC/DCS/SOS/PM/APC string sequences — those are flagged as
unsupported rather than misread. See the roadmap for what's next.

## License

MIT, see [LICENSE](LICENSE).
