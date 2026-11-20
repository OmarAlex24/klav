//! Access to the operating system CSPRNG.

/// Fills `buf` with bytes from the operating system CSPRNG.
///
/// # Panics
///
/// Panics if the OS random number generator is unavailable. There is no safe
/// way to continue without randomness, and every crate in our dependency tree
/// (`hpke`, `ed25519-dalek`) makes the same choice.
pub fn fill(buf: &mut [u8]) {
    getrandom::fill(buf).expect("operating system CSPRNG is unavailable");
}

/// Returns `N` bytes from the operating system CSPRNG. See [`fill`].
pub fn array<const N: usize>() -> [u8; N] {
    let mut out = [0u8; N];
    fill(&mut out);
    out
}

/// Returns a uniformly distributed integer in `0..bound` using rejection
/// sampling (no modulo bias).
///
/// # Panics
///
/// Panics if `bound` is zero, or if the OS CSPRNG is unavailable.
pub fn uniform_u32(bound: u32) -> u32 {
    assert!(bound > 0, "uniform_u32 bound must be positive");
    // Largest multiple of `bound` that fits in u32 space; values at or above
    // it are rejected so every residue is equally likely.
    let zone = u32::MAX - (u32::MAX % bound + 1) % bound;
    loop {
        let v = u32::from_be_bytes(array::<4>());
        if v <= zone {
            return v % bound;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn uniform_stays_in_bounds() {
        for bound in [1u32, 2, 3, 7, 10, 7776, u32::MAX] {
            for _ in 0..200 {
                assert!(uniform_u32(bound) < bound);
            }
        }
    }

    #[test]
    fn arrays_are_not_constant() {
        assert_ne!(array::<32>(), array::<32>());
    }
}
