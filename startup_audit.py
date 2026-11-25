"""
startup_audit.py - checks which programs start automatically, using Microsoft's free Autoruns tool.

Public API (used by audit4all.py):
    find_tool()        -> path to autorunsc, or None
    download_tool()    -> downloads + verifies Autoruns from Microsoft into ./tools
    audit_startup()    -> {"findings": [...], "normal": [...], "stats": {"entries": n}}
    explain_startup(r) -> (plain-English summary, source label)
"""
import csv
import io
import logging
import os
import re
import subprocess
import zipfile

import requests

logger = logging.getLogger(__name__)

HERE = os.path.dirname(os.path.abspath(__file__))
TOOLS_DIR = os.path.join(HERE, "tools")
AUTORUNS_URL = "https://download.sysinternals.com/files/Autoruns.zip"
TOOL_NAMES = ("autorunsc64.exe", "autorunsc.exe")
NO_WINDOW = 0x08000000

RISK_RANK = {"High": 0, "Medium": 1}

# An unknown program that starts from one of these places deserves a second look.
RISKY_PATH_HINTS = (
    "\\temp\\", "\\appdata\\local\\temp\\", "\\downloads\\", "\\users\\public\\",
    "\\$recycle.bin\\", "\\windows\\temp\\", "\\programdata\\temp\\",
)
# Launch-string patterns that are rarely used by honest startup programs.
SUSPICIOUS_LAUNCH = (
    "-enc ", "-encodedcommand", "frombase64string", "-windowstyle hidden", "-w hidden",
    "mshta", "bitsadmin", "certutil -urlcache", "regsvr32 /s /n /u /i:http", "invoke-expression",
    "downloadstring", "http://", "https://",
)


# --------------------------------------------------------------------------- tool management
def find_tool():
    if os.name != "nt":
        return None
    for name in TOOL_NAMES:
        path = os.path.join(TOOLS_DIR, name)
        if os.path.isfile(path):
            return path
    return None


def _verify_signature(path):
    """Raise unless the file carries a valid Microsoft Authenticode signature."""
    ps = (
        f"$s = Get-AuthenticodeSignature -LiteralPath '{path}'; "
        "Write-Output $s.Status; Write-Output $s.SignerCertificate.Subject"
    )
    out = subprocess.run(
        ["powershell", "-NoProfile", "-Command", ps],
        capture_output=True, text=True, timeout=60, creationflags=NO_WINDOW,
    )
    lines = [ln.strip() for ln in out.stdout.splitlines() if ln.strip()]
    status = lines[0] if lines else ""
    subject = lines[1] if len(lines) > 1 else ""
    if status != "Valid" or "microsoft corporation" not in subject.lower():
        raise RuntimeError(f"Downloaded file is not genuinely signed by Microsoft (status: {status or 'unknown'}).")


def download_tool():
    """Download Autoruns, pull out only the command-line tools, and verify them."""
    if os.name != "nt":
        raise RuntimeError("The startup check only works on Windows.")
    os.makedirs(TOOLS_DIR, exist_ok=True)
    resp = requests.get(AUTORUNS_URL, timeout=60)
    resp.raise_for_status()
    wanted = {n.lower(): n for n in TOOL_NAMES}
    saved = []
    with zipfile.ZipFile(io.BytesIO(resp.content)) as zf:
        for member in zf.namelist():
            base = os.path.basename(member).lower()
            if base in wanted and member == os.path.basename(member):  # no sub-folders / path tricks
                dest = os.path.join(TOOLS_DIR, wanted[base])
                with open(dest, "wb") as fh:
                    fh.write(zf.read(member))
                saved.append(dest)
    if not saved:
        raise RuntimeError("The download did not contain the expected tool.")
    try:
        for path in saved:
            _verify_signature(path)
    except Exception:
        for path in saved:
            try:
                os.remove(path)
            except OSError:
                pass
        raise
    logger.info("Autoruns downloaded and verified: %s", saved)


# --------------------------------------------------------------------------- running + parsing
def _decode(raw):
    if raw[:2] in (b"\xff\xfe", b"\xfe\xff") or (len(raw) > 3 and raw[1:2] == b"\x00"):
        return raw.decode("utf-16", errors="replace")
    for enc in ("utf-8-sig", "cp1252"):
        try:
            return raw.decode(enc)
        except UnicodeDecodeError:
            continue
    return raw.decode("utf-8", errors="replace")


def _run_autoruns():
    tool = find_tool()
    if not tool:
        raise RuntimeError("Autoruns tool not found. Use the one-time setup first.")
    proc = subprocess.run(
        [tool, "-accepteula", "-nobanner", "-a", "*", "-c", "-s"],
        capture_output=True, timeout=420, creationflags=NO_WINDOW,
    )
    text = _decode(proc.stdout)
    if "Entry Location" not in text:
        err = _decode(proc.stderr).strip()[:300]
        raise RuntimeError(f"Autoruns returned no usable data (exit {proc.returncode}). {err}")
    return text


def parse_autoruns_csv(text):
    """Turn Autoruns CSV into a list of simple dicts."""
    start = text.find("Time,Entry Location")
    reader = csv.DictReader(io.StringIO(text[start:] if start > 0 else text))
    rows = []
    for r in reader:
        rows.append({
            "location": (r.get("Entry Location") or "").strip(),
            "entry": (r.get("Entry") or "").strip(),
            "enabled": (r.get("Enabled") or "").strip().lower(),
            "category": (r.get("Category") or "").strip(),
            "description": (r.get("Description") or "").strip(),
            "signer": (r.get("Signer") or "").strip(),
            "company": (r.get("Company") or "").strip(),
            "path": (r.get("Image Path") or "").strip(),
            "launch": (r.get("Launch String") or "").strip(),
        })
    return rows


def _short(text, n=120):
    text = " ".join((text or "").split())
    return text if len(text) <= n else text[: n - 1] + "\u2026"


def score_entry(row):
    """Return (score, reasons). Higher = more worth a look. Microsoft-verified entries score 0."""
    signer = row["signer"]
    low_signer = signer.lower()
    verified = low_signer.startswith("(verified)")
    if verified and "microsoft" in low_signer:
        return 0, []

    path_low = row["path"].lower()
    launch_low = (row["launch"] or "").lower() + " "
    score, reasons = 0, []

    missing = path_low.startswith("file not found")
    if not verified and not missing:  # a missing file can't be signed, so that alone says nothing
        score += 1
        reasons.append("not digitally signed or the signature could not be verified")
    if any(h in path_low for h in RISKY_PATH_HINTS):
        score += 2
        reasons.append("runs from a temporary or downloads folder")
    if not verified and any(tok in launch_low for tok in SUSPICIOUS_LAUNCH):
        score += 2
        reasons.append("its start command uses tricks that honest programs rarely use")
    if missing:
        score += 1
        reasons.append("the program file it points to is missing")
    return score, reasons


def analyze_rows(rows):
    findings, normal, seen = [], [], set()
    entries = 0
    for row in rows:
        if not (row["entry"] or row["path"]):
            continue
        entries += 1
        if row["enabled"] and row["enabled"] != "enabled":
            continue  # switched off, so it will not run
        key = (row["entry"].lower(), row["path"].lower(), row["location"].lower())
        if key in seen:
            continue
        seen.add(key)

        score, reasons = score_entry(row)
        name = row["entry"] or os.path.basename(row["path"]) or "Unnamed entry"

        if score >= 2:
            risk = "High" if score >= 4 else "Medium"
            findings.append({
                "risk": risk,
                "title": f"{name} starts automatically",
                "what": (f"'{name}' ({row['description'] or row['category'] or 'startup entry'}) "
                         "launches by itself when your computer starts."),
                "why": "It " + "; ".join(reasons) + ". Most programs like this are harmless, "
                       "but this is a common place for unwanted software to hide.",
                "fix": ("If you recognize it, you can leave it. If not, open Task Manager > Startup apps "
                        "and disable it, then run a malware scan."),
                "evidence": [
                    f"Entry:   {_short(name, 80)}",
                    f"Where:   {_short(row['location'], 80)}",
                    f"File:    {_short(row['path'], 100)}",
                    f"Signer:  {_short(row['signer'] or 'none', 80)}",
                ] + ([f"Command: {_short(row['launch'], 110)}"] if row["launch"] else []),
            })
        else:
            who = row["company"] or re.sub(r"^\((?:Not )?[Vv]erified\)\s*", "", row["signer"]) or ""
            note = ""
            if score == 1:
                note = " (not signed)" if not path_low_missing(row) else " (file missing)"
            label = f"{name}" + (f" \u2014 {who}" if who else "") + note
            if label not in normal:
                normal.append(label)

    findings.sort(key=lambda f: (RISK_RANK[f["risk"]], f["title"].lower()))
    return {"findings": findings[:15], "normal": normal[:200], "stats": {"entries": entries}}


def path_low_missing(row):
    return row["path"].lower().startswith("file not found")


def audit_startup():
    return analyze_rows(parse_autoruns_csv(_run_autoruns()))


# --------------------------------------------------------------------------- plain-English summary
def _rule_summary(findings):
    if not findings:
        return "Nothing unusual starts on its own when your computer turns on. You're fine."
    top = findings[0]
    extra = len(findings) - 1
    more = f" There {'is' if extra == 1 else 'are'} {extra} other thing{'s' if extra != 1 else ''} to glance at too." if extra else ""
    return (f"One startup program is worth a quick look: {top['title'].replace(' starts automatically', '')}. "
            f"{top['fix']}{more} Everything else that starts on its own looks normal.")


def explain_startup(result):
    findings = result["findings"]
    if not findings:
        return _rule_summary(findings), "Deterministic Rule Engine"
    fallback = _rule_summary(findings)
    try:
        from backend import groq_rewrite
    except ImportError:
        return fallback, "Deterministic Rule Engine"
    facts = "\n".join(f"- {f['title']}: {f['risk']} risk. Action: {f['fix']}" for f in findings[:5])
    prompt = (
        "Findings from a Windows startup-programs check:\n"
        f"{facts}\n\n"
        "Answer whether the user is being hacked or spied on in plain, calm everyday English.\n"
        "Rules:\n1. Use 3 to 5 short sentences. No bullet points. No markdown.\n"
        "2. If the findings are minor, say so explicitly and never alarm the reader.\n"
        "3. Do not mention file paths, technical jargon, or product names the user won't recognize.\n"
        "4. End with one clear, calm next step."
    )
    text, label = groq_rewrite(prompt, allowed_ips=(), allowed_ports=())
    return (text, label) if text else (fallback, label)
