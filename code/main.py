"""Evidence-grounded sample and full-dataset audit with explicit release failures."""
import argparse
from pathlib import Path
import sys
import time


def main():
    parser = argparse.ArgumentParser(description="Evidence-grounded deletion audit baseline")
    parser.add_argument('--demo', action='store_true', help='Run the bundled fictional dataset; no API or OCR required')
    parser.add_argument('--competition-output', action='store_true', help='Explicitly enable the legacy challenge CSV workflow')
    parser.add_argument("--check-foundation", action="store_true")
    parser.add_argument("--samples", action="store_true", help="Audit the 32 public sample requests only")
    parser.add_argument("--full", action="store_true", help="Audit all 518 evaluation requests (default)")
    parser.add_argument("--diagnostic", action="store_true", help="Save all assessments without writing root output.csv")
    parser.add_argument("--best-effort", action="store_true", help="Emit qualified candidates with separate uncertainty/partial-plan diagnostics")
    parser.add_argument("--strict",action="store_true",help="Full mode: emit only strict releases instead of the default best-effort candidate")
    parser.add_argument('--conditional-review',action='store_true',help='Include qualified presence-only/ownership-gated predictions (default for non-strict full runs; opt-in for samples); see diagnostics')
    parser.add_argument("--dataset", type=Path, default=Path(__file__).resolve().parents[1]/"dataset")
    parser.add_argument("--run-dir", type=Path)
    parser.add_argument("--no-cache", action="store_true")
    parser.add_argument('--ai-assisted',action='store_true',help='Optional bounded Gemini source-field interpreter; deterministic fallback on every failure')
    parser.add_argument('--gemini-model', help='Explicit model identifier verified by the operator; no assumed default')
    parser.add_argument('--gemini-max-requests',type=int,default=3)
    parser.add_argument('--gemini-max-total-tokens',type=int,default=24000)
    parser.add_argument('--gemini-timeout',type=float,default=20)
    parser.add_argument('--gemini-total-seconds',type=float,default=90)
    parser.add_argument('--gemini-cache-only',action='store_true')
    parser.add_argument('--gemini-input-usd-per-million',type=float)
    parser.add_argument('--gemini-output-usd-per-million',type=float)
    args = parser.parse_args()
    if args.demo and (args.samples or args.full or args.competition_output or args.ai_assisted):
        parser.error('--demo cannot be combined with challenge modes or AI inference')
    if not args.competition_output and (args.best_effort or args.conditional_review):
        parser.error('Candidate predictions require --competition-output; default reports withhold unresolved decisions')
    if args.ai_assisted and not args.gemini_model:
        parser.error('--ai-assisted requires an explicitly verified --gemini-model')
    if not args.competition_output and not args.check_foundation:
        from audit.portfolio import run
        return run(args)
    if args.samples and args.full:parser.error('Choose --samples or --full')
    if args.strict and args.best_effort:parser.error('Choose --strict or --best-effort')
    if args.strict and args.conditional_review:parser.error('Conditional review is unavailable in strict mode')
    if args.conditional_review:args.best_effort=True
    if not args.samples and not args.strict:args.best_effort=args.conditional_review=True
    if not args.check_foundation:
        from audit.inputs import load_dataset
        from audit.planner import Auditor
        from audit.reporting import write_run
        start=time.perf_counter()
        root=Path(__file__).resolve().parents[1]
        mode='samples' if args.samples else 'full'
        args.run_dir=args.run_dir or root/'evaluation/runs'/('samples_final' if args.samples else 'full_final')
        data=load_dataset(args.dataset, None if args.no_cache else root/".audit-cache",'sample_deletion_requests.csv' if args.samples else 'deletion_requests.csv')
        expected=32 if args.samples else 518
        if len(data.requests)!=expected: parser.error(f"{mode} mode requires exactly {expected} supplied requests")
        auditor=Auditor(data)
        if args.ai_assisted:
            from audit.gemini import Config,GeminiClient
            from audit.ai_evidence import AssistedAuditor
            try:
                config=Config(model=args.gemini_model,max_requests=args.gemini_max_requests,max_total_tokens=args.gemini_max_total_tokens,
                              timeout_seconds=args.gemini_timeout,total_seconds=args.gemini_total_seconds,cache_only=args.gemini_cache_only,
                              input_usd_per_million=args.gemini_input_usd_per_million,output_usd_per_million=args.gemini_output_usd_per_million)
            except ValueError as error:parser.error(str(error))
            auditor=AssistedAuditor(data,args.dataset,GeminiClient(config,root/'.audit-cache/gemini'),root/'.audit-cache')
        assessments=[auditor.audit(r) for r in data.requests]
        ai_report=auditor.report() if args.ai_assisted else None
        report=write_run(args.run_dir,assessments,data,time.perf_counter()-start,mode,model_usage=ai_report)
        if ai_report:
            from audit.serialize import atomic_write
            import json
            atomic_write(args.run_dir/'ai_usage.json',json.dumps(ai_report,indent=2,sort_keys=True).encode())
            print(f"AI interpreter: {ai_report['successful_model_calls']} live successful calls, {ai_report['accepted_new_findings']} new grounded findings; {ai_report['rejected_findings']} rejected; cache hits {ai_report['cache_hits']}")
        candidate_report=None
        if args.best_effort:
            from audit.candidates import write_candidates
            candidate_report=write_candidates(args.run_dir,assessments,data.requests,args.conditional_review)
        candidate_bytes=None
        if not args.samples and candidate_report is not None:
            from audit.serialize import csv_bytes
            try:
                candidate_bytes=csv_bytes([c['row'] for c in candidate_report['cases'] if c['row']],
                                          {r.case_id for r in data.requests})
            except (ValueError,TypeError,KeyError):
                print('Full candidate structural validation failed; root output.csv is preserved.')
        if not args.samples and not args.diagnostic and (not args.best_effort or candidate_bytes is not None):
            from audit.serialize import atomic_write
            atomic_write(root/'output.verified.csv',(args.run_dir/'resolved_predictions.csv').read_bytes())
            atomic_write(root/'output.csv',candidate_bytes if args.best_effort else (args.run_dir/'resolved_predictions.csv').read_bytes())
        print(f"{mode} audit: {report['resolved_count']}/{expected} resolved; {len(data.facts)} facts; diagnostics: {args.run_dir/'diagnostics.md'}")
        if candidate_report:print(f"Best-effort candidates: {candidate_report['candidate_rows']}/{expected}; these are not certified complete plans; details: {args.run_dir/'candidate_diagnostics.md'}")
        if not args.samples and args.best_effort:
            if candidate_bytes is not None:
                print(f'Structurally valid {expected}-row candidate published; {report["resolved_count"]}/{expected} strict assessments resolved. Semantic compliance is not certified.')
                return 0
            return 2
        return 0 if report["resolved_count"]==expected else 2
    from audit.contracts import Resource, make_step, order_steps
    from audit.validate import validate_steps
    steps = order_steps([make_step("VERIFICATION", "VERIFY_RECORD_ABSENT", Resource("fixture_service", "fixture_record"), "fixture_evidence")])
    validate_steps("COMPLETE", steps)
    print("Foundation contract validation passed; no dataset predictions executed.")
    return 0


if __name__ == "__main__": sys.exit(main())
