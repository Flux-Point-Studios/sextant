//! Coverage accounting for the sampled STM-membership discharge audit (`sextant-audit`): how much of
//! the certified set a PASSING sample actually discharges. A quantified, uncoercible bound — never
//! "30/30 looks fine". Each of the `k` sampled transactions is proven STM-stake-quorum-certified (a
//! Mithril `CardanoTransactions` inclusion proof recomputed against a genesis-anchored root), so a
//! sample that passes bounds — at a chosen confidence — the fraction of the set that could be
//! undetected phantom transactions. This is the down-payment on the full `AncillarySigned →
//! StmCertified` discharge: the full recompute proves EVERY member; this proves a random sample and
//! publishes exactly how much that buys.
//!
//! The bound is over distinct TX_IDS (a fabricated transaction), not per-output indices of a real
//! transaction — the inclusion proof attests transaction existence, per `verify_tx_inclusion`.

/// The (1 − `alpha`)-confidence upper bound on the FRACTION of the set's distinct members that could
/// be undetected phantoms, after `k` independent membership proofs (all passing) drawn uniformly
/// WITHOUT replacement.
///
/// If a fraction `f` of the members were phantom, a uniform `k`-sample without replacement misses
/// all of them with probability `C(N−P, k) / C(N, k) ≤ ((N−P)/N)^k = (1−f)^k` — the
/// with-replacement envelope, which OVER-estimates the miss probability (sampling without
/// replacement is likelier to hit a phantom), so the bound it yields is CONSERVATIVE. Setting
/// `(1−f)^k = alpha` and solving: `f = 1 − alpha^(1/k)`. All `k` passing therefore gives
/// (1 − `alpha`) confidence that the phantom fraction is below this value. Monotone decreasing in
/// `k` (more proofs ⇒ tighter). `k == 0` ⇒ `1.0` (no evidence); `alpha` is clamped to `(0, 1)`.
pub fn phantom_fraction_bound(k: u32, alpha: f64) -> f64 {
    if k == 0 {
        return 1.0;
    }
    let alpha = alpha.clamp(f64::MIN_POSITIVE, 1.0 - f64::EPSILON);
    1.0 - alpha.powf(1.0 / f64::from(k))
}

/// The (1 − `alpha`)-confidence upper bound on the COUNT of undetected phantom members among `n`
/// distinct members, given `k` passing proofs. Rounds UP — the honest (conservative) direction — and
/// is capped by the EXACT combinatorial ceiling `n − k`: `k` distinct members were proven real, so at
/// most the `n − k` unchecked ones can be phantom (this makes the bound exactly `0` at full coverage
/// `k == n`, where the probabilistic envelope would otherwise report a spurious residual).
pub fn max_undetected_phantoms(n: u64, k: u32, alpha: f64) -> u64 {
    let envelope = (n as f64 * phantom_fraction_bound(k, alpha)).ceil() as u64;
    envelope.min(n.saturating_sub(u64::from(k)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn no_proofs_bound_nothing() {
        assert_eq!(phantom_fraction_bound(0, 0.01), 1.0);
        assert_eq!(max_undetected_phantoms(1000, 0, 0.01), 1000);
    }

    #[test]
    fn the_bound_tightens_as_the_sample_grows() {
        let a = 0.01;
        let b30 = phantom_fraction_bound(30, a);
        let b300 = phantom_fraction_bound(300, a);
        let b3000 = phantom_fraction_bound(3000, a);
        assert!(b30 > b300 && b300 > b3000, "{b30} {b300} {b3000}");
        // 99%-confidence envelopes: ~14% at k=30, ~1.5% at k=300, ~0.15% at k=3000.
        assert!((b30 - 0.1418).abs() < 0.005, "b30={b30}");
        assert!((b300 - 0.0151).abs() < 0.001, "b300={b300}");
        assert!(b3000 < 0.0016, "b3000={b3000}");
    }

    #[test]
    fn tighter_confidence_widens_the_bound() {
        // Demanding MORE confidence (smaller alpha) gives a WEAKER (larger) fraction bound at fixed k.
        assert!(phantom_fraction_bound(100, 0.001) > phantom_fraction_bound(100, 0.05));
    }

    #[test]
    fn full_coverage_is_an_exact_zero_bound() {
        // Proving every distinct member (k == n) leaves NO room for a phantom — exact, not the
        // probabilistic floor the (1-f)^k envelope would report.
        assert_eq!(max_undetected_phantoms(1000, 1000, 0.01), 0);
        // Near-full coverage is capped by n - k (you have only 5 unchecked members).
        assert_eq!(max_undetected_phantoms(1000, 995, 0.01), 5);
    }

    #[test]
    fn count_bound_scales_with_the_set() {
        // At k=300, 99% confidence, < ~1.5% of the ~1.68M-tx_id preprod set are phantom.
        let n = 1_679_960;
        let bound = max_undetected_phantoms(n, 300, 0.01);
        assert!(bound > 20_000 && bound < 30_000, "bound={bound}");
        // Ten times the sample bounds ten-fold fewer phantoms (envelope is exponential in k).
        assert!(max_undetected_phantoms(n, 3000, 0.01) < bound / 5);
    }
}
