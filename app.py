"""CSPM dashboard backend: AWS credentials in -> Prowler API -> findings out.

Run:  PROWLER_EMAIL=you@example.com PROWLER_PASSWORD='...' uvicorn app:app --host 127.0.0.1 --port 9000
"""
import os
import time
from collections import Counter

import boto3
import httpx
from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse
from pydantic import BaseModel

BASE = os.getenv("PROWLER_API", "http://localhost:8080/api/v1")
EMAIL, PASSWORD = os.getenv("PROWLER_EMAIL"), os.getenv("PROWLER_PASSWORD")
MAX_FINDINGS = int(os.getenv("MAX_FINDINGS", "5000"))
J = "application/vnd.api+json"

app = FastAPI(title="CSPM Dashboard")
_tok = {"v": None}
_cache = {}  # scan_id -> normalized findings


def login():
    r = httpx.post(f"{BASE}/tokens", headers={"Content-Type": J, "Accept": J}, timeout=30,
                   json={"data": {"type": "tokens", "attributes": {"email": EMAIL, "password": PASSWORD}}})
    if r.status_code != 200:
        raise HTTPException(502, f"Prowler login failed ({r.status_code}): {r.text[:300]}")
    _tok["v"] = r.json()["data"]["attributes"]["access"]


def prowler(method, path, body=None, params=None, retry=True):
    if not _tok["v"]:
        login()
    r = httpx.request(method, f"{BASE}{path}", params=params, json=body, timeout=120,
                      headers={"Authorization": f"Bearer {_tok['v']}", "Accept": J, "Content-Type": J})
    if r.status_code == 401 and retry:  # access token expired
        login()
        return prowler(method, path, body, params, False)
    if r.status_code >= 400:
        raise HTTPException(r.status_code, r.text[:600])
    return r.json() if r.content else {}


def provider_of(scan):
    return ((scan.get("relationships", {}).get("provider", {}) or {}).get("data") or {}).get("id")


def all_scans():
    return prowler("GET", "/scans", params={"sort": "-inserted_at", "page[size]": 100})["data"]


def start_scan(pid):
    r = prowler("POST", "/scans", {"data": {"type": "scans", "attributes": {"name": "dashboard-scan"},
                "relationships": {"provider": {"data": {"type": "providers", "id": pid}}}}})
    return r["data"]["id"]


class Creds(BaseModel):
    alias: str = ""
    access_key_id: str
    secret_access_key: str
    session_token: str | None = None


@app.post("/api/accounts")
def add_account(c: Creds):
    # 1. Validate the keys with AWS and learn the account ID (the client never types it).
    try:
        sts = boto3.client("sts", aws_access_key_id=c.access_key_id,
                           aws_secret_access_key=c.secret_access_key, aws_session_token=c.session_token)
        acct = sts.get_caller_identity()["Account"]
    except Exception as e:
        raise HTTPException(400, f"AWS rejected these credentials: {e}")
    # 2. Register the account in Prowler and hand over the credentials (not stored here).
    pid = prowler("POST", "/providers", {"data": {"type": "providers", "attributes": {
        "provider": "aws", "uid": acct, "alias": c.alias or acct}}})["data"]["id"]
    secret = {"aws_access_key_id": c.access_key_id, "aws_secret_access_key": c.secret_access_key}
    if c.session_token:
        secret["aws_session_token"] = c.session_token
    prowler("POST", "/providers/secrets", {"data": {"type": "provider-secrets", "attributes": {
        "secret_type": "static", "secret": secret, "name": f"{acct}-credentials"},
        "relationships": {"provider": {"data": {"type": "providers", "id": pid}}}}})
    # 3. Ask Prowler to test the connection, wait for the result, then scan.
    prowler("POST", f"/providers/{pid}/connection")
    conn = {}
    for _ in range(20):
        time.sleep(2)
        conn = prowler("GET", f"/providers/{pid}")["data"]["attributes"].get("connection") or {}
        if conn.get("connected") is not None:
            break
    if not conn.get("connected"):
        raise HTTPException(400, "Prowler could not connect to this account. Check the IAM user's read-only policies.")
    return {"provider_id": pid, "account_id": acct, "scan_id": start_scan(pid)}


@app.get("/api/accounts")
def accounts():
    scans = all_scans()
    out = []
    for p in prowler("GET", "/providers")["data"]:
        a = p["attributes"]
        s = next((x for x in scans if provider_of(x) == p["id"]), None)
        out.append({"id": p["id"], "account_id": a.get("uid"), "alias": a.get("alias"),
                    "connected": (a.get("connection") or {}).get("connected"),
                    "scan_state": s["attributes"]["state"] if s else None})
    return out


@app.delete("/api/accounts/{pid}")
def remove_account(pid: str):
    prowler("DELETE", f"/providers/{pid}")
    return {"deleted": pid}


@app.post("/api/scan/{pid}")
def rescan(pid: str):
    return {"scan_id": start_scan(pid)}


def fetch_findings(scan_id):
    out, page = [], 1
    while len(out) < MAX_FINDINGS:
        r = prowler("GET", "/findings", params={"filter[scan]": scan_id, "include": "resources",
                                                "page[size]": 500, "page[number]": page})
        res = {i["id"]: i["attributes"] for i in r.get("included", []) if i.get("type") == "resources"}
        for f in r["data"]:
            a = f["attributes"]
            md = a.get("check_metadata") or {}
            rid = ((f.get("relationships", {}).get("resources", {}) or {}).get("data") or [{}])[0].get("id")
            ra = res.get(rid, {})
            rec = (md.get("remediation") or {}).get("recommendation") or {}
            out.append({"id": f["id"], "status": a.get("status"), "severity": a.get("severity"),
                        "muted": bool(a.get("muted")), "check_id": a.get("check_id"),
                        "title": md.get("checktitle") or a.get("check_id"),
                        "service": md.get("servicename") or ra.get("service"),
                        "region": ra.get("region"), "resource": ra.get("uid") or ra.get("name"),
                        "message": a.get("status_extended"), "risk": md.get("risk"),
                        "fix": rec.get("text"), "fix_url": rec.get("url")})
        if not (r.get("links") or {}).get("next"):
            break
        page += 1
    return out


def summarize(f):
    fails = [x for x in f if x["status"] == "FAIL" and not x["muted"]]
    by = lambda k: dict(Counter(x[k] or "unknown" for x in fails).most_common())
    top = Counter((x["check_id"], x["title"]) for x in fails).most_common(10)
    return {"total": len(f), "fail": len(fails), "pass": sum(x["status"] == "PASS" for x in f),
            "severity": by("severity"), "service": by("service"), "region": by("region"),
            "top_checks": [{"check_id": k[0], "title": k[1], "count": n} for k, n in top]}


@app.get("/api/data/{pid}")
def data(pid: str, refresh: bool = False):
    mine = [s for s in all_scans() if provider_of(s) == pid]
    if not mine:
        return {"latest_state": None, "summary": None, "findings": []}
    done = next((s for s in mine if s["attributes"]["state"] == "completed"), None)
    resp = {"latest_state": mine[0]["attributes"]["state"], "summary": None, "findings": []}
    if done:
        sid = done["id"]
        if refresh or sid not in _cache:
            _cache[sid] = fetch_findings(sid)
        resp.update(summary=summarize(_cache[sid]), findings=_cache[sid],
                    completed_at=done["attributes"].get("completed_at"))
    return resp


@app.get("/")
def index():
    return FileResponse(os.path.join(os.path.dirname(__file__), "index.html"))
