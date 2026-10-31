# Prepare to explain the project

Work through these in order using the synthetic demo. Do not memorize claims you cannot trace to code.

1. Run the demo. Explain why `demo_changed_email` is INCOMPLETE despite the reported workflow status being COMPLETE. Follow the historical alias into the marketing SQL snapshot.
2. Trace one record from `audit.inputs.load_dataset` through normalization, `IdentityGraph.resolve`, `Auditor.audit` and `audit.portfolio.review_report`.
3. Explain observation time versus availability time. Move the demo's future snapshot before the cutoff in a scratch copy and inspect how the result changes.
4. Explain why the disputed-owner and backup cases abstain. Identify the missing proof needed to resolve each one.
5. Read one independent regression test, change its fixture, predict the result, then run it. Make a small improvement yourself and explain the diff.

Keep a clear distinction between policy status, completeness of the proposed plan, and whether a source actually supports a citation. Passing structural validation does not establish all three.
