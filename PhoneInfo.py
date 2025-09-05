#!/usr/bin/env python3
"""
Phone Investigator — Menu-only, investigator-focused phone intelligence tool.

Features:
- Parse & validate phone numbers (phonenumbers).
- Optional Twilio Lookup & NumVerify integration (if you provide keys).
- Spam / fraud public checks (WhoCallsMe, Tellows) + optional third-party spam API.
- Social enumeration (DuckDuckGo site: queries, Instagram topsearch) — best-effort.
- Local-breach search + optional HaveIBeenPwned (HIBP) phone endpoint (if you have key).
- Phone -> breach -> email pivot and email OSINT (site searches).
- Location approximation by Indian prefix (loadable CSV).
- VoIP / disposable detection (Twilio/NumVerify + heuristics).
- SMS gateway detection via prefix heuristics.
- Fraud risk scoring with explanation.
- Persistent caching (SQLite) to reduce repeated API calls.
- Batch mode with concurrency and export (JSON / CSV / TXT / Graph CSV).
- Robust error handling and menu-driven UI.
"""

import os
import sys
import json
import csv
import time
import sqlite3
import logging
import concurrent.futures
from typing import Any, Dict, List, Optional, Tuple
from datetime import datetime

# Third-party
try:
    import requests
    from dotenv import load_dotenv
    from pyfiglet import Figlet
    from termcolor import colored
    import phonenumbers
    from phonenumbers import carrier, geocoder, timezone
    from bs4 import BeautifulSoup
except Exception as e:
    print("Missing dependency:", e)
    print("Install with: pip install phonenumbers python-dotenv requests pyfiglet termcolor beautifulsoup4")
    sys.exit(1)

load_dotenv()

# ---------------- logging ----------------
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("phone-investigator")

# ---------------- network session w/ retries ----------------
from requests.adapters import HTTPAdapter, Retry

def setup_session(timeout: int = 15) -> requests.Session:
    s = requests.Session()
    retries = Retry(total=2, backoff_factor=0.4, status_forcelist=(429, 500, 502, 503, 504))
    s.mount("https://", HTTPAdapter(max_retries=retries))
    s.mount("http://", HTTPAdapter(max_retries=retries))
    s.headers.update({"User-Agent": "PhoneInvestigator/1.0 (OSINT)"})
    s.timeout = timeout
    return s

SESSION = setup_session()

# ---------------- config / env ----------------
TW_SID = os.getenv("TWILIO_ACCOUNT_SID")
TW_TOKEN = os.getenv("TWILIO_AUTH_TOKEN")
NUMVERIFY_KEY = os.getenv("NUMVERIFY_API_KEY")
HIBP_KEY = os.getenv("HIBP_API_KEY")
SPAM_API_URL = os.getenv("SPAM_API_URL")
SPAM_API_KEY = os.getenv("SPAM_API_KEY")

# ---------------- cache (sqlite) ----------------
CACHE_DB_PATH = ".phoneintel_cache.db"

class SimpleCache:
    def __init__(self, path: str = CACHE_DB_PATH):
        self.path = path
        self.conn = sqlite3.connect(self.path, check_same_thread=False)
        self._init_table()

    def _init_table(self):
        cur = self.conn.cursor()
        cur.execute("""CREATE TABLE IF NOT EXISTS cache (
                        key TEXT PRIMARY KEY,
                        value TEXT,
                        ts INTEGER
                    )""")
        self.conn.commit()

    def get(self, key: str, ttl_seconds: Optional[int]=None) -> Optional[Any]:
        cur = self.conn.cursor()
        cur.execute("SELECT value, ts FROM cache WHERE key=?", (key,))
        row = cur.fetchone()
        if not row:
            return None
        value_text, ts = row
        if ttl_seconds is not None and (time.time() - ts) > ttl_seconds:
            # expired
            cur.execute("DELETE FROM cache WHERE key=?", (key,))
            self.conn.commit()
            return None
        try:
            return json.loads(value_text)
        except Exception:
            return value_text

    def set(self, key: str, value: Any):
        cur = self.conn.cursor()
        val_text = json.dumps(value, ensure_ascii=False)
        cur.execute("INSERT OR REPLACE INTO cache (key, value, ts) VALUES (?, ?, ?)", (key, val_text, int(time.time())))
        self.conn.commit()

    def clear(self):
        cur = self.conn.cursor()
        cur.execute("DELETE FROM cache")
        self.conn.commit()

CACHE = SimpleCache()

# ---------------- small datasets & heuristics ----------------
# Small built-in prefix map for India (prefix -> (operator, circle))
PREFIX_MAP = {
    "9876": ("Airtel", "Haryana"),
    "9820": ("Vodafone Idea", "Mumbai"),
    "9845": ("Jio", "Karnataka"),
    "9810": ("Vodafone Idea", "Delhi"),
    "9800": ("Jio", "West Bengal"),
    "9840": ("Airtel", "Tamil Nadu"),
    # Add your own via menu option (CSV load)
}

VOIP_KEYWORDS = ["google voice", "textnow", "skype", "twilio", "plivo", "vonage", "voip", "sip"]
SMS_GATEWAY_PREFIXES = {"4471", "4472", "9199"}  # sample; expand with real dataset

# Mock local breach DB (you can replace by loading a file via menu)
LOCAL_BREACH_FILE: Optional[str] = None  # path (set via menu)

# ---------------- helpers ----------------
def banner():
    fig = Figlet(font="slant")
    print(colored(fig.renderText("Phone Investigator"), "cyan"))
    print(colored("🔎 Investigator-focused phone OSINT — menu interface\n", "yellow"))

def now_iso() -> str:
    return datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")

def safe_json(resp: requests.Response) -> Any:
    try:
        return resp.json()
    except Exception:
        return None

# ---------------- parsing & prefix mapping ----------------
def parse_number(raw: str, default_region: str = "IN") -> Dict[str, Any]:
    raw = raw.strip()
    out: Dict[str, Any] = {"input_raw": raw}
    try:
        pn = phonenumbers.parse(raw, default_region)
    except phonenumbers.NumberParseException as e:
        out.update({"valid": False, "error": f"Parse error: {e}"})
        return out

    out.update({
        "valid": phonenumbers.is_valid_number(pn),
        "possible": phonenumbers.is_possible_number(pn),
        "e164": phonenumbers.format_number(pn, phonenumbers.PhoneNumberFormat.E164) if phonenumbers.is_valid_number(pn) else None,
        "international": phonenumbers.format_number(pn, phonenumbers.PhoneNumberFormat.INTERNATIONAL) if phonenumbers.is_possible_number(pn) else None,
        "national": phonenumbers.format_number(pn, phonenumbers.PhoneNumberFormat.NATIONAL) if phonenumbers.is_possible_number(pn) else None,
        "region_code": phonenumbers.region_code_for_number(pn),
        "number_type": str(phonenumbers.number_type(pn)),
        "time_zones": timezone.time_zones_for_number(pn),
        "geocoder": geocoder.description_for_number(pn, "en"),
        "indicative_carrier": carrier.name_for_number(pn, "en")
    })

    # prefix mapping for India
    e164 = out.get("e164") or raw
    digits = ''.join(ch for ch in e164 if ch.isdigit())
    local = digits[2:] if digits.startswith("91") and len(digits) > 10 else digits[-10:] if len(digits) >= 10 else digits
    found = {"prefix": None, "operator": None, "circle": None}
    # try longest prefix (5->4->3)
    for L in (5,4,3):
        p = local[:L]
        if p in PREFIX_MAP:
            found["prefix"] = p
            found["operator"], found["circle"] = PREFIX_MAP[p]
            break
    out["prefix_mapping"] = found
    return out

def load_prefix_csv(path: str) -> int:
    # CSV: prefix,operator,circle
    added = 0
    if not os.path.isfile(path):
        raise FileNotFoundError(path)
    with open(path, "r", encoding="utf-8", errors="ignore") as fh:
        for line in fh:
            line=line.strip()
            if not line or line.startswith("#"):
                continue
            parts = [p.strip() for p in line.split(",")]
            if len(parts) >= 3:
                PREFIX_MAP[parts[0]] = (parts[1], parts[2])
                added += 1
    return added

# ---------------- Twilio & NumVerify (safe) ----------------
def twilio_lookup(e164: str) -> Dict[str, Any]:
    cache_key = f"twilio:{e164}"
    cached = CACHE.get(cache_key, ttl_seconds=60*60*24*30)  # cache 30 days
    if cached:
        return cached
    if not (TW_SID and TW_TOKEN):
        res = {"enabled": False, "note": "Twilio credentials not configured"}
        CACHE.set(cache_key, res)
        return res
    try:
        url = f"https://lookups.twilio.com/v2/PhoneNumbers/{e164}"
        r = SESSION.get(url, params={"fields":"carrier,caller_name"}, auth=(TW_SID, TW_TOKEN), timeout=SESSION.timeout)
        data = safe_json(r) or {}
        out = {"enabled": True, "status": r.status_code, "raw": data}
        # normalize expected fields
        out["carrier"] = data.get("carrier") if isinstance(data.get("carrier"), (dict, str)) else data.get("carrier")
        out["caller_name"] = data.get("caller_name")
        CACHE.set(cache_key, out)
        return out
    except Exception as e:
        return {"enabled": True, "error": str(e)}

def numverify_lookup(e164: str) -> Dict[str, Any]:
    cache_key = f"numverify:{e164}"
    cached = CACHE.get(cache_key, ttl_seconds=60*60*24*30)
    if cached:
        return cached
    if not NUMVERIFY_KEY:
        res = {"enabled": False, "note": "NumVerify API key not configured"}
        CACHE.set(cache_key, res)
        return res
    try:
        number = e164[1:] if e164.startswith("+") else e164
        url = "http://apilayer.net/api/validate"
        r = SESSION.get(url, params={"access_key": NUMVERIFY_KEY, "number": number}, timeout=SESSION.timeout)
        data = safe_json(r) or {}
        out = {"enabled": True, "status": r.status_code, "raw": data, "carrier": data.get("carrier"), "line_type": data.get("line_type"), "country_code": data.get("country_code")}
        CACHE.set(cache_key, out)
        return out
    except Exception as e:
        return {"enabled": True, "error": str(e)}

# ---------------- VoIP & SMS detection ----------------
def detect_voip_and_sms(e164: str, tw_res: Dict[str, Any], nv_res: Dict[str, Any]) -> Dict[str, Any]:
    voip = False
    reasons: List[str] = []
    sms_suspected = False
    # numverify line_type
    if nv_res.get("enabled") and nv_res.get("raw"):
        lt = (nv_res.get("raw") or {}).get("line_type") or nv_res.get("line_type")
        if lt and "voip" in str(lt).lower():
            voip = True
            reasons.append(f"numverify_line_type={lt}")
    # twilio carrier type
    if tw_res.get("enabled") and tw_res.get("raw"):
        car = (tw_res.get("raw") or {}).get("carrier") or tw_res.get("carrier")
        if isinstance(car, dict):
            typ = car.get("type")
            name = car.get("name")
            if typ and "voip" in str(typ).lower():
                voip = True
                reasons.append(f"twilio_carrier_type={typ}")
            if name:
                low = str(name).lower()
                for kw in VOIP_KEYWORDS:
                    if kw in low:
                        voip = True
                        reasons.append(f"carrier_name_contains={kw}")
        elif isinstance(car, str):
            low = car.lower()
            for kw in VOIP_KEYWORDS:
                if kw in low:
                    voip = True
                    reasons.append(f"carrier_name_contains={kw}")
    # prefix SMS gateway heuristics
    digits = ''.join(ch for ch in e164 if ch.isdigit())
    local = digits[2:] if digits.startswith("91") and len(digits)>10 else digits[-10:]
    prefix4 = local[:4]
    if prefix4 in SMS_GATEWAY_PREFIXES:
        sms_suspected = True
        reasons.append(f"prefix_{prefix4}_in_sms_gateway_list")
    return {"voip": voip, "reasons": reasons, "sms_suspected": sms_suspected}

# ---------------- Spam check (public scrapes + optional API) ----------------
def who_calls_me(e164: str) -> Dict[str, Any]:
    out = {"source": "whocallsme", "found": False, "items": []}
    num_only = ''.join(ch for ch in e164 if ch.isdigit())
    try:
        url = f"https://whocallsme.com/Phone.aspx?PhoneNumber={num_only}"
        r = SESSION.get(url, timeout=SESSION.timeout)
        if r.status_code == 200:
            soup = BeautifulSoup(r.text, "html.parser")
            posts = soup.select(".post") or soup.select(".single-post") or []
            out["items"] = [p.get_text(separator=" ", strip=True) for p in posts[:8]]
            out["found"] = bool(out["items"])
    except Exception as e:
        out["error"] = str(e)
    return out

def tellows(e164: str) -> Dict[str, Any]:
    out = {"source": "tellows", "found": False, "items": []}
    num_only = ''.join(ch for ch in e164 if ch.isdigit())
    try:
        url = f"https://www.tellows.co.uk/number/{num_only}"
        r = SESSION.get(url, timeout=SESSION.timeout)
        if r.status_code == 200:
            soup = BeautifulSoup(r.text, "html.parser")
            comments = soup.select(".comment") or soup.select(".commentBody") or []
            out["items"] = [c.get_text(separator=" ", strip=True) for c in comments[:8]]
            out["found"] = bool(out["items"])
    except Exception as e:
        out["error"] = str(e)
    return out

def spam_api_lookup(e164: str) -> Dict[str, Any]:
    if not SPAM_API_URL:
        return {"enabled": False, "note": "No SPAM_API_URL configured"}
    try:
        headers = {}
        if SPAM_API_KEY:
            headers["Authorization"] = f"Bearer {SPAM_API_KEY}"
        r = SESSION.get(SPAM_API_URL, params={"number": e164}, headers=headers, timeout=SESSION.timeout)
        try:
            data = r.json()
        except Exception:
            data = {"text": r.text[:1000]}
        return {"enabled": True, "status": r.status_code, "data": data}
    except Exception as e:
        return {"enabled": True, "error": str(e)}

def aggregate_spam(e164: str) -> Dict[str, Any]:
    # run lightweight scrapes concurrently
    results = {}
    try:
        with concurrent.futures.ThreadPoolExecutor(max_workers=3) as ex:
            futs = {
                ex.submit(who_calls_me, e164): "whocallsme",
                ex.submit(tellows, e164): "tellows",
                ex.submit(spam_api_lookup, e164): "spam_api"
            }
            for fut in concurrent.futures.as_completed(futs):
                k = futs[fut]
                try:
                    results[k] = fut.result()
                except Exception as e:
                    results[k] = {"error": str(e)}
    except Exception as e:
        results["error"] = str(e)
    return results

# ---------------- social enumeration (best-effort) ----------------
DDG_HTML = "https://html.duckduckgo.com/html/"

def ddg_site_search(query: str, site: Optional[str] = None, limit: int = 6) -> List[str]:
    cache_key = f"ddg:{site or 'any'}:{query}"
    cached = CACHE.get(cache_key, ttl_seconds=60*60*24)  # 1 day
    if cached:
        return cached
    q = query if not site else f"site:{site} {query}"
    try:
        r = SESSION.post(DDG_HTML, data={"q": q}, timeout=SESSION.timeout)
        links = []
        if r.status_code == 200:
            soup = BeautifulSoup(r.text, "html.parser")
            # try specific anchor class
            for a in soup.select("a.result__a")[:limit]:
                href = a.get("href")
                if href:
                    links.append(href)
            # fallback
            if not links:
                for a in soup.select("a")[:limit*3]:
                    href = a.get("href")
                    if href and (not site or site in href):
                        links.append(href)
        CACHE.set(cache_key, links)
        return links[:limit]
    except Exception:
        return []

def instagram_topsearch(e164: str) -> Dict[str, Any]:
    cache_key = f"igtop:{e164}"
    cached = CACHE.get(cache_key, ttl_seconds=60*60*24)
    if cached:
        return cached
    try:
        url = f"https://www.instagram.com/web/search/topsearch/?query={e164}"
        r = SESSION.get(url, timeout=SESSION.timeout)
        if r.status_code == 200:
            try:
                data = r.json()
                CACHE.set(cache_key, {"success": True, "raw": data})
                return {"success": True, "raw": data}
            except Exception:
                CACHE.set(cache_key, {"success": False, "status": r.status_code})
                return {"success": False, "status": r.status_code}
        else:
            CACHE.set(cache_key, {"success": False, "status": r.status_code})
            return {"success": False, "status": r.status_code}
    except Exception as e:
        return {"success": False, "error": str(e)}

def social_enum(e164: str) -> Dict[str, Any]:
    out = {}
    out["instagram_topsearch"] = instagram_topsearch(e164)
    out["facebook_results"] = ddg_site_search(e164, "facebook.com", limit=5)
    out["instagram_results"] = ddg_site_search(e164, "instagram.com", limit=5)
    out["linkedin_results"] = ddg_site_search(e164, "linkedin.com", limit=5)
    out["telegram_results"] = ddg_site_search(e164, "t.me", limit=5)
    return out

# ---------------- breach checks ----------------
def breach_local_search(e164: str, breach_file: Optional[str]) -> Dict[str, Any]:
    if not breach_file or not os.path.isfile(breach_file):
        return {"enabled": False, "note": "No local breach file configured"}
    found = []
    target = ''.join(ch for ch in e164 if ch.isdigit())
    try:
        with open(breach_file, "r", encoding="utf-8", errors="ignore") as fh:
            for line in fh:
                if target in ''.join(ch for ch in line if ch.isdigit()):
                    found.append(line.strip())
        return {"enabled": True, "matches": found, "count": len(found)}
    except Exception as e:
        return {"enabled": True, "error": str(e)}

def hibp_phone_check(e164: str) -> Dict[str, Any]:
    cache_key = f"hibp:{e164}"
    cached = CACHE.get(cache_key, ttl_seconds=60*60*24*7)
    if cached:
        return cached
    if not HIBP_KEY:
        res = {"enabled": False, "note": "No HIBP API key configured"}
        CACHE.set(cache_key, res)
        return res
    try:
        phone = ''.join(ch for ch in e164 if ch.isdigit())
        url = f"https://haveibeenpwned.com/api/v3/phone/{phone}/breaches"
        headers = {"hibp-api-key": HIBP_KEY, "user-agent": "PhoneInvestigator/1.0"}
        r = SESSION.get(url, headers=headers, timeout=SESSION.timeout)
        if r.status_code == 200:
            data = safe_json(r) or []
            out = {"enabled": True, "status": 200, "breaches": data}
            CACHE.set(cache_key, out)
            return out
        else:
            out = {"enabled": True, "status": r.status_code, "note": "Non-200 from HIBP (check subscription/endpoint)"}
            CACHE.set(cache_key, out)
            return out
    except Exception as e:
        return {"enabled": True, "error": str(e)}

# ---------------- pivot email -> OSINT ----------------
def pivot_email_osint(email: str) -> Dict[str, Any]:
    cache_key = f"pivot_email:{email}"
    cached = CACHE.get(cache_key, ttl_seconds=60*60*24)
    if cached:
        return cached
    result = {"email": email, "social": {}}
    # search linkedin, github, facebook, instagram via DDG
    result["social"]["linkedin"] = ddg_site_search(email, "linkedin.com", limit=5)
    result["social"]["github"] = ddg_site_search(email, "github.com", limit=5)
    result["social"]["facebook"] = ddg_site_search(email, "facebook.com", limit=5)
    result["social"]["instagram"] = ddg_site_search(email, "instagram.com", limit=5)
    CACHE.set(cache_key, result)
    return result

# ---------------- fraud risk scoring ----------------
def compute_risk(result: Dict[str, Any]) -> Dict[str, Any]:
    # weights (tweakable)
    weights = {
        "spam_reports": 30,
        "local_breach": 30,
        "hibp_breaches": 25,
        "voip": 20,
        "social_presence": 10
    }
    score = 0
    reasons: List[str] = []
    # spam
    spam = result.get("spam", {})
    spam_count = 0
    if spam.get("whocallsme", {}).get("items"):
        spam_count += len(spam["whocallsme"]["items"])
    if spam.get("tellows", {}).get("items"):
        spam_count += len(spam["tellows"]["items"])
    third = spam.get("spam_api", {})
    if third and third.get("data"):
        # heuristic: if third-party returns 'score' or 'reports' adjust
        d = third.get("data")
        if isinstance(d, dict) and (d.get("reports") or d.get("count")):
            spam_count += int(d.get("reports") or d.get("count"))
    if spam_count >= 5:
        score += weights["spam_reports"]
        reasons.append(f"spam_reports={spam_count}")
    # local breach
    lb = result.get("breach", {}).get("local", {})
    if lb.get("enabled") and lb.get("count", 0) > 0:
        score += weights["local_breach"]
        reasons.append(f"local_breach_count={lb.get('count')}")
    # hibp
    hb = result.get("breach", {}).get("hibp", {})
    if hb.get("enabled") and hb.get("breaches"):
        num = len(hb.get("breaches") or [])
        score += min(weights["hibp_breaches"], num * 10)
        reasons.append(f"hibp_breaches={num}")
    # voip
    if result.get("voip_detection", {}).get("voip"):
        score += weights["voip"]
        reasons.append("voip_detected")
    # social presence (if lots of social hits)
    social = result.get("social", {})
    social_hits = 0
    for k,v in social.items():
        if isinstance(v, list):
            social_hits += len(v)
        elif isinstance(v, dict) and v.get("raw"):
            # instagram topsearch raw interpretation skipped; give +1 if present
            if v.get("raw"):
                social_hits += 1
    if social_hits >= 3:
        score += weights["social_presence"]
        reasons.append(f"social_hits={social_hits}")
    final = min(int(score), 100)
    return {"score": final, "reasons": reasons, "weights_used": weights}

# ---------------- graph export (nodes/edges CSV) ----------------
def export_graph_csv(results: List[Dict[str, Any]], out_prefix: str):
    # nodes.csv: id,label,type
    # edges.csv: source,target,relation
    nodes = {}
    edges = []
    def add_node(id_val: str, label: str, ntype: str):
        if id_val not in nodes:
            nodes[id_val] = {"id": id_val, "label": label, "type": ntype}
    for r in results:
        phone = r.get("input") or (r.get("parsed") or {}).get("e164") or r.get("input_raw")
        if not phone:
            continue
        add_node(phone, phone, "phone")
        # breaches -> emails
        lb = r.get("breach", {}).get("local", {})
        if lb.get("enabled") and lb.get("matches"):
            for m in lb["matches"]:
                # try to extract email from string (simple heuristic)
                import re
                emails = re.findall(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}", m)
                for em in emails:
                    add_node(em, em, "email")
                    edges.append((phone, em, "leak_email"))
        hb = r.get("breach", {}).get("hibp", {})
        if hb.get("enabled") and hb.get("breaches"):
            # HIBP returns breach entries; try to attach generic node
            for b in hb.get("breaches"):
                bname = b.get("Name") or b.get("Title") or str(b)
                nid = f"breach:{bname}"
                add_node(nid, bname, "breach")
                edges.append((phone, nid, "found_in_breach"))
                # emails within breaches — check for added emails via pivot (not automatic)
        # social links
        social = r.get("social", {})
        # ddg lists return URLs; add as nodes
        for key in ("facebook_results", "instagram_results", "linkedin_results", "telegram_results"):
            for url in social.get(key, []) or []:
                add_node(url, url, "social")
                edges.append((phone, url, "social_hit"))
        # pivoted emails via breach pivot (if present)
        pivots = r.get("pivot_emails") or {}
        for em, pdata in pivots.items():
            add_node(em, em, "email")
            edges.append((phone, em, "leak_email_pivot"))
            for site, hits in (pdata.get("social") or {}).items():
                for site_url in hits:
                    add_node(site_url, site_url, "social")
                    edges.append((em, site_url, f"email_to_{site}"))
    # write CSVs
    nodes_file = f"{out_prefix}_nodes.csv"
    edges_file = f"{out_prefix}_edges.csv"
    with open(nodes_file, "w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh)
        w.writerow(["id", "label", "type"])
        for n in nodes.values():
            w.writerow([n["id"], n["label"], n["type"]])
    with open(edges_file, "w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh)
        w.writerow(["source", "target", "relation"])
        for s,t,rel in edges:
            w.writerow([s,t,rel])
    return nodes_file, edges_file

# ---------------- orchestration: analyze one number ----------------
def analyze_number(input_number: str, breach_file: Optional[str] = None) -> Dict[str, Any]:
    result: Dict[str, Any] = {"input": input_number, "checked_at": now_iso()}
    parsed = parse_number(input_number)
    result["parsed"] = parsed
    if not parsed.get("valid"):
        result["note"] = "Invalid number; analysis limited."
        return result
    e164 = parsed.get("e164")
    result["input"] = e164
    # twilio & numverify
    tw = twilio_lookup(e164)
    nv = numverify_lookup(e164)
    result["twilio"] = tw
    result["numverify"] = nv
    # spam
    spam = aggregate_spam(e164)
    result["spam"] = spam
    # social
    social = social_enum(e164)
    result["social"] = social
    # prefix mapping (from parsed["prefix_mapping"])
    result["location"] = parsed.get("prefix_mapping", {})
    # voip & sms detection
    voip = detect_voip_and_sms(e164, tw, nv)
    result["voip_detection"] = voip
    # breaches local + hibp
    local_breach = breach_local_search(e164, breach_file)
    hibp = hibp_phone_check(e164)
    result["breach"] = {"local": local_breach, "hibp": hibp}
    # pivot emails from local breach matches (simple extraction)
    pivot_emails = {}
    if local_breach.get("enabled") and local_breach.get("matches"):
        import re
        for row in local_breach.get("matches", []):
            emails = re.findall(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}", row)
            for em in emails:
                if em not in pivot_emails:
                    pivot_emails[em] = pivot_email_osint(em)
    # also pivot on breaches from HIBP if available and contains emails (HIBP breach entries may include data but phone endpoint might not return emails)
    result["pivot_emails"] = pivot_emails
    # compute risk
    risk = compute_risk(result)
    result["risk"] = risk
    return result

# ---------------- batch processing ----------------
def process_batch_file(inpath: str, out_json: Optional[str], out_csv: Optional[str], breach_file: Optional[str]):
    if not os.path.isfile(inpath):
        print("Input file not found.")
        return []
    with open(inpath, "r", encoding="utf-8", errors="ignore") as fh:
        numbers = [line.strip() for line in fh if line.strip()]
    if not numbers:
        print("No numbers found.")
        return []
    max_workers = min(20, max(4, len(numbers)//2))
    results = []
    print(f"Processing {len(numbers)} numbers with {max_workers} workers...")
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as ex:
        futures = {ex.submit(analyze_number, n, breach_file): n for n in numbers}
        for fut in concurrent.futures.as_completed(futures):
            n = futures[fut]
            try:
                res = fut.result()
                results.append(res)
            except Exception as e:
                logger.exception("Error processing %s: %s", n, e)
                results.append({"input": n, "error": str(e)})
    # exports
    if out_json:
        with open(out_json, "w", encoding="utf-8") as fh:
            json.dump(results, fh, indent=2, ensure_ascii=False)
        print("Wrote JSON:", out_json)
    if out_csv:
        # simple flat CSV
        headers = ["input","e164","valid","operator","circle","voip","sms_suspected","spam_notes","local_breach_count","hibp_breaches","risk_score","checked_at"]
        rows = []
        for r in results:
            parsed = r.get("parsed", {})
            e164 = parsed.get("e164")
            valid = parsed.get("valid")
            location = r.get("location", {})
            op = location.get("operator")
            circle = location.get("circle")
            voip = r.get("voip_detection", {}).get("voip")
            sms = r.get("voip_detection", {}).get("sms_suspected")
            spam_notes = 0
            spam_notes += len(r.get("spam", {}).get("whocallsme", {}).get("items", []))
            spam_notes += len(r.get("spam", {}).get("tellows", {}).get("items", []))
            local_breach_count = r.get("breach", {}).get("local", {}).get("count", 0)
            hibp_count = len(r.get("breach", {}).get("hibp", {}).get("breaches") or [])
            risk_score = r.get("risk", {}).get("score")
            checked = r.get("checked_at")
            rows.append([r.get("input"), e164, valid, op, circle, voip, sms, spam_notes, local_breach_count, hibp_count, risk_score, checked])
        with open(out_csv, "w", newline="", encoding="utf-8") as fh:
            w = csv.writer(fh)
            w.writerow(headers)
            w.writerows(rows)
        print("Wrote CSV:", out_csv)
    return results

# ---------------- save helpers (JSON/CSV/TXT) ----------------
def save_single_result(result: Dict[str, Any]):
    want = input("Save result? (y/n): ").strip().lower()
    if want != "y":
        return
    fmt = input("Format (json/csv/txt): ").strip().lower()
    fname = input("Filename (without extension): ").strip()
    if fmt == "json":
        with open(f"{fname}.json", "w", encoding="utf-8") as fh:
            json.dump(result, fh, indent=2, ensure_ascii=False)
        print("Saved:", f"{fname}.json")
    elif fmt == "csv":
        # write flattened single-row CSV with key:value
        with open(f"{fname}.csv", "w", newline="", encoding="utf-8") as fh:
            w = csv.writer(fh)
            w.writerow(["key","value"])
            for k,v in result.items():
                w.writerow([k, json.dumps(v, ensure_ascii=False)])
        print("Saved:", f"{fname}.csv")
    elif fmt == "txt":
        with open(f"{fname}.txt", "w", encoding="utf-8") as fh:
            fh.write(json.dumps(result, indent=2, ensure_ascii=False))
        print("Saved:", f"{fname}.txt")
    else:
        print("Unknown format.")

# ---------------- menu ----------------
def interactive_menu():
    history: List[Dict[str, Any]] = []
    global LOCAL_BREACH_FILE
    while True:
        banner()
        print("Menu:")
        print("1) Parse & validate single number")
        print("2) Full single-number analysis (all checks)")
        print("3) Batch analyze numbers from file")
        print("4) Load prefix map CSV (prefix,operator,circle)")
        print("5) Set / clear local breach file (for breach checks)")
        print("6) Show last results summary")
        print("7) Export history (JSON/CSV/TXT)")
        print("8) Export graph (nodes/edges CSV) from history")
        print("9) Clear cache")
        print("0) Exit")
        choice = input("\nEnter choice: ").strip()

        if choice == "0":
            print("Goodbye.")
            break

        if choice == "1":
            n = input("Enter number (e.g., +919876543210): ").strip()
            p = parse_number(n)
            print(json.dumps(p, indent=2, ensure_ascii=False))
            save = input("Save parsed result? (y/n): ").strip().lower()
            if save == "y":
                fname = f"parsed_{int(time.time())}"
                with open(f"{fname}.json", "w", encoding="utf-8") as fh:
                    json.dump(p, fh, indent=2, ensure_ascii=False)
                print("Saved:", fname + ".json")
            input("Press Enter to continue...")

        elif choice == "2":
            n = input("Enter number (e.g., +919876543210): ").strip()
            print("[*] Running full analysis — this may take a few seconds.")
            res = analyze_number(n, LOCAL_BREACH_FILE)
            print(json.dumps(res, indent=2, ensure_ascii=False))
            history.append(res)
            save_single_result(res)
            input("Press Enter to continue...")

        elif choice == "3":
            path = input("Enter input file path (one number per line): ").strip()
            outj = input("Optional output JSON filename (leave blank to skip): ").strip() or None
            outc = input("Optional output CSV filename (leave blank to skip): ").strip() or None
            batch = process_batch_file(path, outj, outc, LOCAL_BREACH_FILE)
            if batch:
                history.extend(batch)
            input("Press Enter to continue...")

        elif choice == "4":
            path = input("Enter prefix CSV path (prefix,operator,circle). Leave blank to cancel: ").strip()
            if path:
                try:
                    added = load_prefix_csv(path)
                    print(f"Loaded {added} prefixes.")
                except Exception as e:
                    print("Failed to load prefix CSV:", e)
            input("Press Enter to continue...")

        elif choice == "5":
            print("Current breach file:", LOCAL_BREACH_FILE or "(not set)")
            sub = input("Type 'set' to set path, 'clear' to unset: ").strip().lower()
            if sub == "set":
                p = input("Enter local breach file path: ").strip()
                if os.path.isfile(p):
                    LOCAL_BREACH_FILE = p
                    print("Set local breach file.")
                else:
                    print("File not found.")
            elif sub == "clear":
                LOCAL_BREACH_FILE = None
                print("Cleared breach file.")
            input("Press Enter to continue...")

        elif choice == "6":
            if not history:
                print("No history yet.")
            else:
                print("Last results (up to 10):")
                for r in history[-10:]:
                    parsed = r.get("parsed", {})
                    print(f"- {r.get('input')} | valid={parsed.get('valid')} | operator={r.get('location',{}).get('operator')} | voip={r.get('voip_detection',{}).get('voip')} | risk={r.get('risk',{}).get('score')}")
            input("Press Enter to continue...")

        elif choice == "7":
            if not history:
                print("No history to export.")
                input("Press Enter to continue...")
                continue
            fmt = input("Format (json/csv/txt): ").strip().lower()
            fname = input("Output filename (without extension): ").strip()
            if fmt == "json":
                with open(f"{fname}.json", "w", encoding="utf-8") as fh:
                    json.dump(history, fh, indent=2, ensure_ascii=False)
                print("Saved:", fname + ".json")
            elif fmt == "csv":
                # reuse batch CSV writer for simplicity
                with open(f"{fname}.csv", "w", newline="", encoding="utf-8") as fh:
                    w = csv.writer(fh)
                    headers = ["input","e164","valid","operator","circle","voip","sms_suspected","spam_notes","local_breach_count","hibp_breaches","risk_score","checked_at"]
                    w.writerow(headers)
                    for r in history:
                        parsed = r.get("parsed", {})
                        e164 = parsed.get("e164")
                        valid = parsed.get("valid")
                        location = r.get("location", {})
                        op = location.get("operator")
                        circle = location.get("circle")
                        voip = r.get("voip_detection", {}).get("voip")
                        sms = r.get("voip_detection", {}).get("sms_suspected")
                        spam_notes = 0
                        spam_notes += len(r.get("spam", {}).get("whocallsme", {}).get("items", []))
                        spam_notes += len(r.get("spam", {}).get("tellows", {}).get("items", []))
                        local_breach = r.get("breach", {}).get("local", {}).get("count", 0)
                        hibp_breaches = len(r.get("breach", {}).get("hibp", {}).get("breaches") or [])
                        risk_score = r.get("risk", {}).get("score")
                        checked = r.get("checked_at")
                        w.writerow([r.get("input"), e164, valid, op, circle, voip, sms, spam_notes, local_breach, hibp_breaches, risk_score, checked])
                print("Saved:", fname + ".csv")
            elif fmt == "txt":
                with open(f"{fname}.txt", "w", encoding="utf-8") as fh:
                    fh.write(json.dumps(history, indent=2, ensure_ascii=False))
                print("Saved:", fname + ".txt")
            else:
                print("Unknown format.")
            input("Press Enter to continue...")

        elif choice == "8":
            if not history:
                print("No history to export.")
                input("Press Enter to continue...")
                continue
            prefix = input("Output file prefix (e.g., graph_out): ").strip()
            nodes_file, edges_file = export_graph_csv(history, prefix)
            print("Nodes:", nodes_file)
            print("Edges:", edges_file)
            input("Press Enter to continue...")

        elif choice == "9":
            confirm = input("Clear local cache? (y/n): ").strip().lower()
            if confirm == "y":
                CACHE.clear()
                print("Cache cleared.")
            input("Press Enter to continue...")

        else:
            print("Unknown option.")
            input("Press Enter to continue...")

# ---------------- main ----------------
if __name__ == "__main__":
    try:
        interactive_menu()
    except KeyboardInterrupt:
        print("\nInterrupted by user. Exiting.")
        sys.exit(0)
