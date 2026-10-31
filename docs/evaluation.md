# Evaluation and reproduction

## Current portfolio verification — 31 October 2026

Run `python run_tests.py` from the project root. On Windows with Python 3.14.6, the current run discovered 173 tests: 171 passed and two challenge integration tests were skipped. This includes six new portfolio tests. No third-party packages were required for that run.

The two skipped tests require an authorized full challenge dataset and document/OCR dependencies. Opt in with environment variable `GHOST_CHALLENGE_TESTS=1`; they are not replaced by synthetic accuracy claims. The test runner is portable across working directories. The demo CLI is tested in isolated subprocesses with `-S` (site packages disabled), from a different working directory, and its two generated JSON reports must be byte-identical.

The new tests establish that:

- Unknown restore safety cannot yield a default COMPLETE label or action plan.
- Disputed ownership yields explicit review, a null public status and no steps.
- The bundled demo traverses actual CSV, JSON, SQLite and log ingestion.
- Historical email resolution finds an old-email marketing record.
- Post-cutoff evidence is not cited as audit-time proof.
- Conditional predictions require explicit competition mode, and CLI inference requires an explicit model.

They do not establish universal evidence coverage or correctness on unseen data. Resolved assessments remain bounded by source coverage and the supported policy schemas.

## Historical challenge submission

The submitted archive reports 29/32 sample status matches, 9/32 exact cases, 156/159 matched predicted steps and 156/193 matched expected steps. Three samples had no prediction. These are stored historical measurements, **not freshly reproduced portfolio results**; public samples guided repeated tuning, so they are not an untouched holdout.

The historical full candidate contained 518 rows. Its stored diagnostics separated 119 strict releases, 242 supported-INCOMPLETE partial plans, 155 observed-scope COMPLETE predictions and two special review candidates. The full dataset was not rerun for this cleanup. No hidden-test score or accuracy improvement is claimed.

The two review patterns prompted the safer portfolio output: uncertain backup restore policy (historical case_55) and disputed record ownership (historical case_63). The original competition path remains available by explicit option; default reporting does not emit their conditional predictions or remediation plans.

## Model usage

The preserved submission used deterministic fallback; its reports record zero inference calls. Optional Gemini code has mocked integration tests. Live inference, current provider model availability and development token/cost accounting remain unverified. No model availability or price is inferred from a configured identifier.
