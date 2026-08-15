"""Run the enrichment pipeline: eve.json -> grouped alerts -> Gemini
explanations -> SQLite. Re-running is cheap: groups already in the database
are skipped, so this is safe to run again after Suricata produces new
alerts.

Usage:
    python analyzer/cli.py [path/to/eve.json]
"""

from __future__ import annotations

import os
import sys

from dotenv import load_dotenv

load_dotenv()

from google import genai

import db
import explain
from ingest import load_alert_groups

DEFAULT_EVE_PATH = os.path.join(os.path.dirname(__file__), "..", "logs", "eve.json")
DB_PATH = os.environ.get("DB_PATH", os.path.join(os.path.dirname(__file__), "alerts.db"))


def main() -> None:
    eve_path = sys.argv[1] if len(sys.argv) > 1 else DEFAULT_EVE_PATH

    if not os.environ.get("GEMINI_API_KEY"):
        print("GEMINI_API_KEY is not set. Copy analyzer/.env.example to "
              "analyzer/.env and add your key, or export it directly.")
        sys.exit(1)

    print(f"Reading {eve_path} ...")
    groups = load_alert_groups(eve_path)
    print(f"Found {len(groups)} distinct alert group(s) "
          f"(from {sum(g.count for g in groups)} raw alert events).")

    client = genai.Client()

    with db.connect(DB_PATH) as conn:
        already_done = db.existing_group_keys(conn)
        new_groups = [g for g in groups if g.group_key not in already_done]
        print(f"{len(already_done)} already enriched, {len(new_groups)} new.")

        for i, group in enumerate(new_groups, start=1):
            print(f"[{i}/{len(new_groups)}] explaining: {group.signature} "
                  f"({group.src_ip} -> {group.dest_ip}:{group.dest_port}, "
                  f"x{group.count}) ...", end=" ", flush=True)
            try:
                explanation = explain.explain_group(client, group)
                db.upsert_group(conn, group, explanation)
                print(f"-> {explanation['severity']}")
            except Exception as e:
                print(f"FAILED: {e}")

    print(f"Done. Dashboard reads from {DB_PATH}.")


if __name__ == "__main__":
    main()
