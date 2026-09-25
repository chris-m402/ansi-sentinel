//! Property-based checks against pseudo-random byte streams.
//!
//! This isn't wired up to `cargo fuzz` (that would pull in a corpus, a
//! nightly toolchain, and a coverage-guided fuzzer as dependencies). What it
//! checks instead: seeded PRNG input run through many iterations, so a
//! regression here is exact and reproducible just by pinning the seed below,
//! no crash corpus to check in.

use ansi_sentinel::csi::parse_csi_params;
use ansi_sentinel::sgr::parse_sgr;
use ansi_sentinel::{EscapeScanner, Event};

/// xorshift64* - small, seedable, and good enough to spread bytes across the
/// scanner's branches without adding a `rand` dependency for it.
struct Rng(u64);

impl Rng {
    fn next_u64(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.0 = x;
        x.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }

    fn below(&mut self, bound: usize) -> usize {
        (self.next_u64() % bound as u64) as usize
    }

    fn byte(&mut self) -> u8 {
        (self.next_u64() & 0xFF) as u8
    }
}

/// Bytes that actually matter to the escape-sequence grammar. Weighting
/// generation toward these (instead of uniform noise) means most runs
/// actually exercise CSI/OSC/DCS parsing instead of producing one big
/// `Event::Text`.
const INTERESTING: &[u8] = b"\x1b[]PX_^\\\x07;:?0123456789mHJKABCDhl ";

fn random_input(rng: &mut Rng, max_len: usize) -> Vec<u8> {
    let len = rng.below(max_len + 1);
    (0..len)
        .map(|_| {
            if rng.below(4) == 0 {
                rng.byte()
            } else {
                INTERESTING[rng.below(INTERESTING.len())]
            }
        })
        .collect()
}

fn reconstruct(events: &[Event<'_>]) -> Vec<u8> {
    events
        .iter()
        .copied()
        .flat_map(|e| match e {
            Event::Text(b) | Event::Escape(b) | Event::Invalid(b) => b.iter().copied(),
        })
        .collect()
}

#[test]
fn lenient_mode_never_errors_and_never_loses_bytes() {
    let mut rng = Rng(0x9E37_79B9_7F4A_7C15);
    for _ in 0..5000 {
        let input = random_input(&mut rng, 64);
        let events: Vec<Event<'_>> = EscapeScanner::lenient(&input)
            .map(|r| r.unwrap_or_else(|e| panic!("lenient mode errored on {input:?}: {e}")))
            .collect();
        assert_eq!(
            reconstruct(&events),
            input,
            "lenient scan did not reconstruct its input: {input:?}"
        );
    }
}

#[test]
fn strict_mode_terminates_without_panicking() {
    let mut rng = Rng(0xD1B5_4A32_D192_ED03);
    for _ in 0..5000 {
        let input = random_input(&mut rng, 64);
        // Every event, Ok or Err, consumes at least one byte (see
        // `EscapeScanner::scan_escape`), so the iterator can never yield
        // more events than there are input bytes. A larger count would mean
        // something stopped advancing `pos` and started looping.
        let count = EscapeScanner::strict(&input).count();
        assert!(
            count <= input.len(),
            "strict scan produced {count} events for {} input bytes: {input:?}",
            input.len()
        );
    }
}

#[test]
fn csi_and_sgr_parsers_never_panic_on_scanner_output() {
    let mut rng = Rng(0x2545_F491_4F6C_DD1D);
    for _ in 0..5000 {
        let input = random_input(&mut rng, 64);
        for event in EscapeScanner::lenient(&input) {
            if let Event::Escape(bytes) = event.expect("lenient mode never errors") {
                let _ = parse_csi_params(bytes);
                let _ = parse_sgr(bytes);
            }
        }
    }
}
