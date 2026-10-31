"""Strict, atomic CSV publication. Partial development files are explicitly named."""
import csv
import io
import json
import os
from pathlib import Path
import tempfile

from .validate import validate_steps

HEADER = ["case_id", "deletion_status", "steps_json"]


def csv_bytes(rows: list[dict], expected_ids: set[str]) -> bytes:
    ids = [r["case_id"] for r in rows]
    if len(ids) != len(set(ids)) or set(ids) != expected_ids:
        raise ValueError("Case coverage/uniqueness mismatch")
    stream = io.StringIO(newline="")
    writer = csv.DictWriter(stream, fieldnames=HEADER, lineterminator="\n")
    writer.writeheader()
    for row in sorted(rows, key=lambda r: r["case_id"]):
        if set(row) != set(HEADER):
            raise ValueError("Unexpected CSV fields")
        steps = row["steps_json"]
        if isinstance(steps, str):
            steps = json.loads(steps)
        validate_steps(row["deletion_status"], steps)
        writer.writerow(dict(row, steps_json=json.dumps(steps, ensure_ascii=False, separators=(",", ":"), allow_nan=False)))
    data = stream.getvalue().encode("utf-8")
    reread = list(csv.DictReader(io.StringIO(data.decode("utf-8"))))
    if len(reread) != len(rows):
        raise ValueError("CSV round trip failed")
    return data


def atomic_write(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary = tempfile.mkstemp(prefix=".audit-", dir=path.parent)
    try:
        with os.fdopen(fd, "wb") as out:
            out.write(data)
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)
