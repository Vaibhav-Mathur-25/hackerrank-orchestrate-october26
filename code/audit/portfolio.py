"""Default review report: unresolved decisions never carry a remediation plan."""
from dataclasses import asdict
import json
from pathlib import Path

from .inputs import load_dataset
from .planner import Auditor
from .serialize import atomic_write, csv_bytes


def review_report(assessments, data):
    cases = []
    for result in sorted(assessments, key=lambda value: value.case_id):
        review = not result.resolved
        issues = [asdict(issue) for issue in result.issues if issue.blocking]
        cases.append({
            'case_id': result.case_id,
            'review_required': review,
            'deletion_status': None if review else result.status,
            'supported_status_before_review': result.status,
            'subject_id': result.subject_id or None,
            'steps': [] if review else result.steps,
            'actions_withheld': review,
            'execution_authorized': False,
            'issues': issues,
        })
    return {
        'schema_version': 1,
        'mode': 'advisory_review',
        'scope': 'Supplied evidence at each audit cutoff; not proof of discovery across live systems.',
        'executes_deletions': False,
        'request_count': len(cases),
        'review_required_count': sum(case['review_required'] for case in cases),
        'input_hashes': data.input_hashes,
        'cases': cases,
    }


def run(args):
    root = Path(__file__).resolve().parents[2]
    dataset_path = root / 'demo/dataset' if args.demo else args.dataset
    request_file = 'sample_deletion_requests.csv' if args.samples else 'deletion_requests.csv'
    if not (dataset_path / request_file).exists():
        raise SystemExit('Dataset not found. Try: python code/main.py --demo (or supply --dataset PATH).')
    data = load_dataset(dataset_path, None if args.demo or args.no_cache else root / '.audit-cache', request_file)
    auditor = Auditor(data)
    if args.ai_assisted:
        from .gemini import Config, GeminiClient
        from .ai_evidence import AssistedAuditor
        try:
            config = Config(model=args.gemini_model, max_requests=args.gemini_max_requests,
                            max_total_tokens=args.gemini_max_total_tokens, timeout_seconds=args.gemini_timeout,
                            total_seconds=args.gemini_total_seconds, cache_only=args.gemini_cache_only,
                            input_usd_per_million=args.gemini_input_usd_per_million,
                            output_usd_per_million=args.gemini_output_usd_per_million)
        except ValueError as error:
            raise SystemExit(str(error)) from error
        auditor = AssistedAuditor(data, dataset_path, GeminiClient(config, root / '.audit-cache/gemini'), root / '.audit-cache')
    assessments = [auditor.audit(request) for request in data.requests]
    report = review_report(assessments, data)
    directory = args.run_dir or root / ('demo-output' if args.demo else 'evaluation/runs/review')
    # This report is the primary output. It includes every request, even abstentions.
    atomic_write(directory / 'audit_report.json', json.dumps(report, indent=2, ensure_ascii=False).encode('utf-8'))
    resolved = [result for result in assessments if result.resolved]
    rows = [{'case_id': result.case_id, 'deletion_status': result.status, 'steps_json': result.steps} for result in resolved]
    atomic_write(directory / 'resolved_predictions.csv', csv_bytes(rows, {result.case_id for result in resolved}))
    if args.ai_assisted:
        atomic_write(directory / 'ai_usage.json', json.dumps(auditor.report(), indent=2).encode('utf-8'))
    print(f"Advisory audit: {len(resolved)}/{len(assessments)} resolved; {report['review_required_count']} require review.")
    print(f'Report: {directory / "audit_report.json"}')
    print('Unresolved verdicts and plans are withheld. No service actions are performed.')
    # A completed review is successful even when it correctly abstains.
    return 0
