#!/usr/bin/env python3
"""HTTP Web Server for Ghost Data Audit Dashboard on port 5158."""
import csv, json, os, subprocess, sys, time, zipfile
from http.server import ThreadingHTTPServer, SimpleHTTPRequestHandler
from pathlib import Path
from urllib.parse import urlparse, parse_qs

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT / "code"))

from audit.util import read_csv
from audit.identity import IdentityResolver

PORT = 5158

class AuditDashboardHandler(SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=str(ROOT / "web"), **kwargs)

    def log_message(self, format, *args):
        sys.stderr.write(f"[Web 5158] {self.address_string()} - {format % args}\n")

    def send_json(self, data, code=200):
        body = json.dumps(data, ensure_ascii=False).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Cache-Control", "no-cache, no-store, must-revalidate")
        self.end_headers()
        self.wfile.write(body)

    def _load_output(self, ds_type):
        out_file = ROOT / ("sample_pred.csv" if ds_type == "sample" else "output.csv")
        if not out_file.exists():
            return []
        return list(csv.DictReader(open(out_file, encoding="utf-8-sig")))

    def _load_requests(self, ds_type):
        req_file = ROOT / "dataset" / ("sample_deletion_requests.csv" if ds_type == "sample" else "deletion_requests.csv")
        if not req_file.exists():
            return {}
        return {r["case_id"]: r for r in read_csv(req_file)}

    def do_GET(self):
        pr = urlparse(self.path)
        path = pr.path
        query = parse_qs(pr.query)

        if path == "/api/health":
            return self.send_json({"status": "ok", "port": PORT, "service": "ghost-data-audit-dashboard", "timestamp": time.time()})

        if path == "/api/stats":
            ds_type = query.get("dataset", ["full"])[0]
            rows = self._load_output(ds_type)
            complete = sum(1 for r in rows if r["deletion_status"] == "COMPLETE")
            incomplete = sum(1 for r in rows if r["deletion_status"] == "INCOMPLETE")
            na = sum(1 for r in rows if r["deletion_status"] == "NOT_APPLICABLE")
            # Phase and operation distributions
            phases = {"FINDING": 0, "REMEDIATION": 0, "VERIFICATION": 0}
            ops = {}
            systems = {}
            step_dist = {}
            total_steps = 0
            for r in rows:
                steps = json.loads(r["steps_json"] or "[]")
                n = len(steps)
                total_steps += n
                step_dist[str(n)] = step_dist.get(str(n), 0) + 1
                for s in steps:
                    ph = s.get("phase", "")
                    phases[ph] = phases.get(ph, 0) + 1
                    op = s.get("operation", "")
                    ops[op] = ops.get(op, 0) + 1
                    sid = s.get("system_id", "")
                    systems[sid] = systems.get(sid, 0) + 1
            return self.send_json({
                "total": len(rows),
                "complete": complete,
                "incomplete": incomplete,
                "not_applicable": na,
                "total_steps": total_steps,
                "avg_steps": round(total_steps / len(rows), 2) if rows else 0,
                "phase_distribution": phases,
                "operation_distribution": dict(sorted(ops.items(), key=lambda x: -x[1])[:12]),
                "system_distribution": dict(sorted(systems.items(), key=lambda x: -x[1])),
                "step_count_distribution": step_dist,
            })

        if path == "/api/cases":
            ds_type = query.get("dataset", ["full"])[0]
            page = int(query.get("page", ["1"])[0])
            per_page = int(query.get("per_page", ["50"])[0])
            status_filter = query.get("status", ["ALL"])[0]
            search = query.get("search", [""])[0].lower()
            sort_by = query.get("sort", ["case_id"])[0]
            sort_dir = query.get("dir", ["asc"])[0]

            req_map = self._load_requests(ds_type)
            rows = self._load_output(ds_type)

            result = []
            for r in rows:
                cid = r["case_id"]
                req = req_map.get(cid, {})
                steps = json.loads(r["steps_json"] or "[]")
                result.append({
                    "case_id": cid,
                    "deletion_status": r["deletion_status"],
                    "email": req.get("email", ""),
                    "requested_at": req.get("requested_at", ""),
                    "reported_status": req.get("reported_status", ""),
                    "audit_at": req.get("audit_at", ""),
                    "step_count": len(steps),
                })

            # Filter
            if status_filter != "ALL":
                result = [c for c in result if c["deletion_status"] == status_filter]
            if search:
                result = [c for c in result if search in c["case_id"].lower() or search in c.get("email", "").lower()]

            total = len(result)

            # Sort
            reverse = sort_dir == "desc"
            if sort_by in ("case_id", "deletion_status", "email", "step_count", "requested_at"):
                result.sort(key=lambda x: (x.get(sort_by) or ""), reverse=reverse)

            # Paginate
            start = (page - 1) * per_page
            paginated = result[start:start + per_page]

            return self.send_json({
                "cases": paginated,
                "total": total,
                "page": page,
                "per_page": per_page,
                "total_pages": max(1, (total + per_page - 1) // per_page),
            })

        if path.startswith("/api/case/"):
            cid = path[len("/api/case/"):]
            ds_type = query.get("dataset", ["full"])[0]
            req_file = ROOT / "dataset" / ("sample_deletion_requests.csv" if ds_type == "sample" else "deletion_requests.csv")
            out_file = ROOT / ("sample_pred.csv" if ds_type == "sample" else "output.csv")

            req_map = {r["case_id"]: r for r in read_csv(req_file)} if req_file.exists() else {}
            out_map = {r["case_id"]: r for r in csv.DictReader(open(out_file, encoding="utf-8-sig"))} if out_file.exists() else {}

            req = req_map.get(cid)
            out_r = out_map.get(cid)
            if not req and not out_r:
                return self.send_json({"error": "Case not found"}, 404)

            ident_data = {}
            if req and req.get("email"):
                resolver = IdentityResolver(ROOT / "dataset")
                ident = resolver.resolve(req["email"], req.get("audit_at", ""))
                if ident:
                    ident_data = {
                        "user_id": ident.user_id,
                        "name": next(iter(ident.names), "") if ident.names else "",
                        "phone": next(iter(ident.phones), "") if ident.phones else "",
                        "email_hash": next(iter(ident.hashes), "") if ident.hashes else "",
                        "all_identifiers": list(ident.all_identifiers())
                    }

            steps = json.loads(out_r["steps_json"] or "[]") if out_r else []
            data = {
                "case_id": cid,
                "deletion_status": out_r["deletion_status"] if out_r else "UNKNOWN",
                "email": req.get("email", "") if req else "",
                "requested_at": req.get("requested_at", "") if req else "",
                "reported_status": req.get("reported_status", "") if req else "",
                "reported_at": req.get("reported_at", "") if req else "",
                "audit_at": req.get("audit_at", "") if req else "",
                "request_text": req.get("request_text", "") if req else "",
                "identity": ident_data,
                "steps": steps,
                "phase_summary": {
                    "FINDING": sum(1 for s in steps if s.get("phase") == "FINDING"),
                    "REMEDIATION": sum(1 for s in steps if s.get("phase") == "REMEDIATION"),
                    "VERIFICATION": sum(1 for s in steps if s.get("phase") == "VERIFICATION"),
                }
            }
            return self.send_json(data)

        if path in ("/api/view/output.csv", "/api/download/output.csv", "/api/download/output_excel.csv"):
            ds_type = query.get("dataset", ["full"])[0]
            target = ROOT / ("sample_pred.csv" if ds_type == "sample" else "output.csv")
            if not target.exists():
                self.send_error(404, "File not found")
                return
            data = target.read_bytes()
            is_view = "/api/view/" in path or query.get("view", ["0"])[0] == "1" or query.get("inline", ["0"])[0] == "1"
            is_excel = "output_excel" in path or query.get("excel", ["0"])[0] == "1"
            if is_excel and not data.startswith(b"\xef\xbb\xbf"):
                data = b"\xef\xbb\xbf" + data
            filename = "output_excel.csv" if is_excel else "output.csv"
            self.send_response(200)
            if is_view:
                self.send_header("Content-Type", "text/plain; charset=utf-8")
                self.send_header("Content-Disposition", f'inline; filename="{filename}"')
            else:
                self.send_header("Content-Type", "text/csv; charset=utf-8")
                self.send_header("Content-Disposition", f'attachment; filename="{filename}"')
            self.send_header("Content-Length", str(len(data)))
            self.send_header("Access-Control-Allow-Origin", "*")
            self.send_header("Cache-Control", "no-cache, no-store, must-revalidate")
            self.end_headers()
            self.wfile.write(data)
            return

        if path == "/api/csv_data":
            ds_type = query.get("dataset", ["full"])[0]
            target = ROOT / ("sample_pred.csv" if ds_type == "sample" else "output.csv")
            if not target.exists():
                return self.send_json({"error": "File not found"}, 404)
            raw = target.read_bytes()
            size = len(raw)
            text_content = raw.decode("utf-8-sig")
            return self.send_json({
                "filename": target.name,
                "raw_text": text_content,
                "size_bytes": size,
                "size_kb": round(size / 1024, 1),
            })

        if path == "/api/open_file":
            filename = query.get("name", ["output.csv"])[0]
            action = query.get("action", ["default"])[0]
            target = (ROOT / filename).resolve()
            if not str(target).startswith(str(ROOT)) or not target.exists():
                return self.send_json({"error": "File not found or access denied"}, 404)
            try:
                if action == "notepad":
                    subprocess.Popen(["notepad.exe", str(target)])
                    return self.send_json({"status": "success", "message": f"Opened {target.name} in Notepad"})
                elif action == "explorer":
                    subprocess.Popen(["explorer.exe", f"/select,{str(target)}"])
                    return self.send_json({"status": "success", "message": f"Showed {target.name} in File Explorer"})
                else:
                    if hasattr(os, "startfile"):
                        os.startfile(str(target))
                    else:
                        subprocess.Popen(["notepad.exe", str(target)])
                    return self.send_json({"status": "success", "message": f"Opened {target.name} with system default"})
            except Exception as e:
                try:
                    subprocess.Popen(["notepad.exe", str(target)])
                    return self.send_json({"status": "success", "message": f"Opened {target.name} in Notepad (fallback)"})
                except Exception as e2:
                    return self.send_json({"error": str(e2)}, 500)

        if path == "/api/zip_contents":
            filename = query.get("name", ["code.zip"])[0]
            target = (ROOT / filename).resolve()
            if not str(target).startswith(str(ROOT)) or not target.exists():
                return self.send_json({"error": "File not found or access denied"}, 404)
            try:
                with zipfile.ZipFile(target, "r") as z:
                    files = []
                    for info in z.infolist():
                        files.append({
                            "filename": info.filename,
                            "file_size": info.file_size,
                            "compress_size": info.compress_size,
                            "is_dir": info.is_dir(),
                            "date_time": f"{info.date_time[0]:04d}-{info.date_time[1]:02d}-{info.date_time[2]:02d} {info.date_time[3]:02d}:{info.date_time[4]:02d}",
                        })
                    return self.send_json({
                        "filename": target.name,
                        "total_files": len(files),
                        "total_uncompressed": sum(f["file_size"] for f in files),
                        "total_compressed": target.stat().st_size,
                        "files": files
                    })
            except Exception as e:
                return self.send_json({"error": str(e)}, 500)

        if path == "/api/download/code.zip":
            target = ROOT / "code.zip"
            if not target.exists():
                self.send_error(404, "File not found")
                return
            data = target.read_bytes()
            self.send_response(200)
            self.send_header("Content-Type", "application/zip")
            self.send_header("Content-Disposition", 'attachment; filename="code.zip"')
            self.send_header("Content-Length", str(len(data)))
            self.send_header("Access-Control-Allow-Origin", "*")
            self.send_header("Cache-Control", "no-cache, no-store, must-revalidate")
            self.end_headers()
            self.wfile.write(data)
            return

        if path == "/api/download/trace.zip":
            target = ROOT / "agent-trace.zip"
            if not target.exists():
                self.send_error(404, "File not found")
                return
            data = target.read_bytes()
            self.send_response(200)
            self.send_header("Content-Type", "application/zip")
            self.send_header("Content-Disposition", 'attachment; filename="agent-trace.zip"')
            self.send_header("Content-Length", str(len(data)))
            self.send_header("Access-Control-Allow-Origin", "*")
            self.send_header("Cache-Control", "no-cache, no-store, must-revalidate")
            self.end_headers()
            self.wfile.write(data)
            return

        return super().do_GET()

    def do_POST(self):
        pr = urlparse(self.path)
        if pr.path == "/api/run":
            content_length = int(self.headers.get("Content-Length", 0))
            body = self.rfile.read(content_length).decode("utf-8") if content_length > 0 else "{}"
            payload = json.loads(body)
            run_type = payload.get("type", "sample")

            t0 = time.time()
            if run_type == "sample":
                cmd = [sys.executable, str(ROOT / "code" / "main.py"), "--sample"]
            else:
                cmd = [sys.executable, str(ROOT / "code" / "run_all.py")]

            proc = subprocess.run(cmd, cwd=str(ROOT), capture_output=True, text=True)
            duration = round(time.time() - t0, 2)

            return self.send_json({
                "status": "success" if proc.returncode == 0 else "error",
                "type": run_type,
                "duration_sec": duration,
                "log": (proc.stdout or "") + (proc.stderr or ""),
                "code": proc.returncode
            })

        self.send_error(404, "Not found")


def run_server():
    server_address = ("0.0.0.0", PORT)
    httpd = ThreadingHTTPServer(server_address, AuditDashboardHandler)
    print(f"Ghost Data Audit Agent Dashboard running live on http://localhost:{PORT}")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\nShutting down server.")
        httpd.server_close()


if __name__ == "__main__":
    run_server()
