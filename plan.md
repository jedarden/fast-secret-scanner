# Benchmark GIF storytelling plan

Owning bead: `fss-501e2518`

## Objective

Turn the README benchmark GIF from a moving comparison chart into a short,
self-explanatory story: one staged line enters, both scanners start together,
the fast local gate completes almost immediately, the comprehensive gate
finishes afterward, and the final frame explains why both layers matter.

The animation must preserve the measured claim—8 ms versus 539 ms on the same
224-byte staged patch—while explicitly stating that the on-screen motion timing
is dramatized.

## Narrative beats

1. **Setup:** Introduce one staged line and two scan lanes.
2. **Anticipation:** Hold both runners at a shared starting gate with a small
   pulse and backward wind-up.
3. **Fast action:** Launch `secret-scanner` with strong acceleration, trailing
   secondary particles, a slight overshoot, and a quick settle.
4. **First payoff:** Pop the measured 8 ms result while Gitleaks remains in
   motion, making the local-feedback benefit immediately legible.
5. **Follow-through:** Ease Gitleaks toward the same finish rather than simply
   stopping it midway.
6. **Final payoff:** Reveal 539 ms, the measured ~67x comparison, and the
   layered message: “Fast first. Comprehensive second.”
7. **Hold and loop:** Leave enough time to read the conclusion, then restart
   from a visually distinct empty-stage frame.

## Animation principles applied

- Staging and visual hierarchy through a shared start, separated lanes, and a
  single finish.
- Anticipation before launch.
- Slow-in/slow-out for Gitleaks and ease-out for the fast scanner.
- Overshoot and settle at the fast finish.
- Secondary action through restrained trails and finish ripples.
- Timing contrast to establish character without pretending the dramatized
  motion duration is the actual benchmark duration.
- Follow-through and a readable final hold before the loop resets.

## Deliverables

- [x] Versioned, text-free visual stage in `assets/`.
- [x] Deterministic FFmpeg animation in `scripts/render-benchmark-gif.sh`.
- [x] Updated `assets/benchmark.gif` referenced by the README.
- [x] Contact-sheet review of setup, launch, first finish, second finish, and
      final hold.
- [ ] Secret scans, formatting checks, bead checkpoint, commit, and Forgejo
      push with GitHub mirror verification.

## Acceptance checks

- The five narrative moments are distinguishable without reading source code.
- Labels remain legible at the README's rendered width.
- Exact claims match `research/benchmark-results.tsv`.
- The footer says the motion timing is dramatized.
- The GIF loops, is 960×540, and remains reasonably sized for a README.
- Gitleaks and `secret-scanner` report no findings in the staged change.
