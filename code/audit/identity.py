"""Resolve a request email to a user and all current + historical identifiers."""
from .util import read_csv, pick, norm, digits, parse_ts


class Identity:
    def __init__(self, user_id):
        self.user_id = user_id
        self.emails, self.phones, self.hashes, self.names = set(), set(), set(), set()
        self.audit_ids = {}  # identifier value -> audit_id that revealed it

    def all_identifiers(self):
        return self.emails | self.phones | self.hashes | self.names


class IdentityResolver:
    def __init__(self, ds):
        self.identities = read_csv(ds / "user_identities.csv")
        self.audit = read_csv(ds / "user_audit_log.csv")

    def resolve(self, email, audit_at):
        e = norm(email)
        uid = None
        for r in self.identities:
            if norm(pick(r, "email")) == e:
                uid = pick(r, "user_id")
                break
        if uid is None:
            for r in self.audit:
                if pick(r, "field").lower() in ("email", "email_address") and e in (norm(pick(r, "old_value")), norm(pick(r, "new_value"))):
                    uid = pick(r, "user_id")
                    break
        if uid is None:
            return None
        ident = Identity(uid)
        for r in self.identities:
            if pick(r, "user_id") == uid:
                self._add(ident, "email", pick(r, "email"))
                self._add(ident, "phone", pick(r, "phone"))
                self._add(ident, "email_hash", pick(r, "email_hash"))
                self._add(ident, "name", pick(r, "name"))
        for r in self.audit:
            if pick(r, "user_id") != uid:
                continue
            ts, cutoff = parse_ts(pick(r, "ts")), parse_ts(audit_at)
            if ts and cutoff and ts > cutoff:
                continue  # changes after audit_at must not influence the case
            f = pick(r, "field").lower()
            kind = {"email": "email", "email_address": "email", "phone": "phone", "phone_number": "phone",
                    "email_hash": "email_hash", "name": "name", "full_name": "name"}.get(f)
            if kind:
                for v in (pick(r, "old_value"), pick(r, "new_value")):
                    self._add(ident, kind, v, pick(r, "audit_id"))
        return ident

    @staticmethod
    def _add(ident, kind, value, audit_id=""):
        if not value:
            return
        v = norm(value) if kind != "phone" else digits(value)
        if not v:
            return
        {"email": ident.emails, "phone": ident.phones, "email_hash": ident.hashes, "name": ident.names}[kind].add(v)
        if audit_id:
            ident.audit_ids.setdefault(v, audit_id)
