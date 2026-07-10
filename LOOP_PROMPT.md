Read LOOP.md in the repo root. It is the loop's single source of state.

Each iteration of this loop starts with a fresh context. Work exactly one
slice per iteration, and a slice is not finished until it is shipped or
explicitly parked:

1. Pick the first unchecked item under Plan. If Plan is empty, derive the
   next smallest slice from the Definition of Done and add it first.
2. TDD, strictly: write the failing test, run it, confirm the exact
   expected failure, then write the minimum code to flip it green.
3. Run scripts/harness.sh --full. Red output is the work list; fix it.
4. Append one row to Evidence for anything claimed: the command run and its
   result, a tx hash, a log excerpt. Unproven claims do not count.
5. Check the finished Plan item off. Commit test and code together with a
   message naming the slice.
6. Ship it per the Merge policy in LOOP.md: push the branch, open or
   update the PR, then red-team the diff (/fluxpoint-loop:red-team, or
   apply the adversarial checklist inline: eUTxO, oracle, authority,
   numeric, off-chain, infra) and post the verdict on the PR.
   VERDICT: BLOCK is harness-red — fix the findings before anything else.
   On SHIP: if policy allows auto-merge, merge (squash), delete the
   branch, and sync the default branch locally; otherwise park the PR
   with a one-line handoff comment and move on. Never end an iteration
   with an unreviewed PR.
7. Update Notes for the next iteration: current state, blockers, and if
   blocked, two alternative paths and which one to attack next.

Set `STATUS: DONE` on line 3 of LOOP.md only when every Definition of Done
line is checked with proof recorded. Never edit the Definition of Done,
the Merge policy, or delete tests to get there. If the same approach has
failed three iterations in a row, write a checkpoint summary in Notes
instead of retrying it a fourth time.
