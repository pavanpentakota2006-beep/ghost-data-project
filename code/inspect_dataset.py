#!/usr/bin/env python3
"""Print the shape of dataset/ (headers, sample rows, evidence types, SQL schemas) to speed up calibration.
Usage: python3 code/inspect_dataset.py [--dataset DIR]"""
import argparse, collections, sqlite3, sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from audit.util import read_csv
from audit.schema import check_dataset


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--dataset", default=str(Path(__file__).resolve().parent.parent / "dataset"))
    ds = Path(ap.parse_args().dataset)
    for p in sorted(ds.glob("*.csv")):
        rows = read_csv(p)
        print(f"\n== {p.name}: {len(rows)} rows")
        if rows:
            print("columns:", list(rows[0].keys()))
            for r in rows[:3]:
                print("  ", dict(r))
    ev = ds / "evidence"
    if ev.exists():
        print("\n== evidence file types:", dict(collections.Counter(f.suffix.lower() for f in ev.rglob("*") if f.is_file())))
        for f in sorted(ev.rglob("*.sql"))[:3]:
            con = sqlite3.connect(":memory:")
            try:
                con.executescript(f.read_text(errors="ignore"))
                for (t,) in con.execute("select name from sqlite_master where type='table'"):
                    print(f"  {f.name}.{t}:", [c[1] for c in con.execute(f'pragma table_info("{t}")')])
            except sqlite3.Error as e:
                print(f"  {f.name}: not executable in SQLite ({e})")
    print("\n== schema warnings:")
    for w in check_dataset(ds) or ["none"]:
        print(" -", w)


if __name__ == "__main__":
    main()
