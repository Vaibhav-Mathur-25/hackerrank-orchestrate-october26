"""Read SQLite exports in memory, with no filesystem SQL operations or extensions."""
from __future__ import annotations
import json
import sqlite3
import re
from ..normalize import TABLE_SYSTEMS, collection_category, record_fact
from .csv_json import scope_fact


def sql_facts(data: bytes, eid: str, captured: str) -> list:
    connection = sqlite3.connect(":memory:")
    def authorize(action, arg1, arg2, db, source):
        if action in {sqlite3.SQLITE_ATTACH, sqlite3.SQLITE_DETACH}: return sqlite3.SQLITE_DENY
        if action == sqlite3.SQLITE_PRAGMA and str(arg1).lower() != "foreign_keys": return sqlite3.SQLITE_DENY
        if action == sqlite3.SQLITE_FUNCTION and str(arg2).lower() in {"load_extension", "readfile", "writefile"}: return sqlite3.SQLITE_DENY
        return sqlite3.SQLITE_OK
    ticks = 0
    def progress():
        nonlocal ticks
        ticks += 1
        return int(ticks > 10000)
    connection.set_authorizer(authorize)
    connection.set_progress_handler(progress, 1000)
    try:
        sql=data.decode("utf-8")
        connection.executescript(sql)
        dump_contract=bool(re.search(r'--[^\n]*point-in-time database snapshot',sql,re.I) and
                           re.search(r'\bBEGIN\s+TRANSACTION\s*;',sql,re.I) and re.search(r'\bCOMMIT\s*;',sql,re.I))
        tables = [r[0] for r in connection.execute("SELECT name FROM sqlite_master WHERE type='table'")]
        scope_systems = None
        if "snapshot_scope" in tables:
            scope_systems = {r[0] for r in connection.execute("SELECT origin_system FROM snapshot_scope")}
        out = []
        for table in sorted(tables):
            if table == "snapshot_scope": continue
            cursor = connection.execute('SELECT * FROM "' + table.replace('"', '""') + '"')
            columns = [c[0] for c in cursor.description]
            records = [dict(zip(columns, r)) for r in cursor.fetchmany(100001)]
            if len(records) > 100000: raise ValueError("SQL row safety limit exceeded")
            is_replica = "replica" in table
            store = table if is_replica else "primary"
            scopes = {}
            if "record_json" not in columns:
                system = TABLE_SYSTEMS.get(table)
                if table.startswith("customer_profiles_"): system = "account_service"
                if not system: raise ValueError("Unsupported SQL table: " + table)
                if scope_systems is not None and system not in scope_systems: continue
                category = collection_category(table)
                scopes[(system, category)] = []
            for i, record in enumerate(records):
                if "record_json" in record:
                    system, collection = record["origin_system"], record["collection_name"]
                    body = json.loads(record["record_json"])
                    if body.get("resource_id") != record["resource_id"]: raise ValueError("Embedded resource_id mismatch")
                    category = collection_category(collection)
                else:
                    body, collection = record, table
                scopes.setdefault((system, category), []).append(body["resource_id"])
                out.append(record_fact(body, evidence_id=eid, locator=f"table:{table}/row:{i}", available=captured,
                                       observed=captured, system=system, collection=collection, category=category, store=store))
            for (system, category), members in scopes.items():
                # A dedicated CREATE/INSERT table in the declared transactional
                # snapshot format is a full table export. Mixed record_json
                # bundles do not declare which collections are exhaustive.
                complete=dump_contract and "record_json" not in columns
                if scope_systems is not None and "record_json" not in columns:
                    scope_time=connection.execute('SELECT captured_at FROM snapshot_scope WHERE origin_system=?',(system,)).fetchone()
                    complete=bool(scope_time and scope_time[0]==captured and re.search(r'\bCOMMIT\s*;',sql,re.I))
                out.append(scope_fact(eid, f"table:{table}", captured, captured, system, category, store, members,complete))
        return out
    finally: connection.close()
