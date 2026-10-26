import csv, re
from datetime import datetime, timezone
from .config import ALIASES


def read_csv(path):
    try:
        with open(path, newline="", encoding="utf-8-sig") as f:
            return list(csv.DictReader(f))
    except UnicodeDecodeError:
        with open(path, newline="", encoding="latin-1") as f:
            return list(csv.DictReader(f))



def pick(row, key, default=""):
    for a in ALIASES.get(key, [key]):
        if a in row and row[a] is not None:
            return row[a].strip() if isinstance(row[a], str) else row[a]
    return default


def parse_ts(s):
    if not s:
        return None
    s = str(s).strip().replace("Z", "+00:00")
    for fmt in (None, "%Y-%m-%d %H:%M:%S", "%Y-%m-%d"):
        try:
            d = datetime.fromisoformat(s) if fmt is None else datetime.strptime(s, fmt)
            return d if d.tzinfo else d.replace(tzinfo=timezone.utc)
        except ValueError:
            continue
    return None


def digits(s):
    return re.sub(r"\D", "", str(s or ""))


def norm(s):
    return str(s or "").strip().lower()
