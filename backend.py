import ctypes
import ipaddress
import json
import logging
import os
import re
import subprocess
import time
import psutil
import requests

LOG_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "audit4all.log")
logging.basicConfig(
    filename=LOG_PATH,
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger(__name__)

try:
    from knowledge_base import analyze_port as _kb_analyze_port
    KNOWLEDGE_BASE_OK = True
except ImportError as exc:
    KNOWLEDGE_BASE_OK = False
    logger.exception("Failed to import knowledge_base: %s", exc)

    def _kb_analyze_port(port, process_name, pid, listen_ip, exe_path=""):
        is_local = listen_ip in ("127.0.0.1", "::1")
        return {
            "port": port,
            "process": process_name,
            "pid": pid,
            "exe": exe_path or "Run as administrator to inspect program location",
            "ip": listen_ip,
            "exposure": "Local only" if is_local else "Network",
            "service": "Background program",
            "plain_title": f"Program listening on port {port}",
            "risk": "Low" if is_local else "Medium",
            "base_risk": "Medium",
            "unknown": True,
            "description": f"The program '{process_name}' is waiting for connections on port {port}.",
            "business_impact": (
                "Protected: Only this computer can reach it."
                if is_local
                else "Other devices on your network may be able to reach this program."
            ),
            "fix": "If you do not recognize this program, close it and run a security scan.",
        }


try:
    import pcap_analyzer as _pcap_analyzer_mod  # noqa: F401
    PCAP_ANALYZER_OK = True
except ImportError as exc:
    PCAP_ANALYZER_OK = False
    logger.exception("Optional pcap_analyzer module not available: %s", exc)


GROQ_BASE_URL = "https://api.groq.com/openai/v1/chat/completions"
GROQ_MODELS = ["openai/gpt-oss-20b", "openai/gpt-oss-120b"]

RISK_RANK = {"High": 0, "Medium": 1, "Low": 2}

# Standard Windows plumbing: always open on every PC, so never worth an alert by itself.
WINDOWS_NORMAL_PORTS = {135, 139, 445, 5040, 5357, 7680}
# An unknown program running from here is suspicious; one in Program Files / WindowsApps is just an installed app.
RISKY_PATH_HINTS = ("\\temp\\", "\\downloads\\", "\\users\\public\\", "\\desktop\\")
FRIENDLY_APPS = {
    "spotify.exe": "Spotify (music app)",
    "spotifylauncher.exe": "Spotify (music app)",
    "wacom_tablet.exe": "Wacom tablet driver",
    "code.exe": "VS Code",
    "armourysocketserver.exe": "ASUS Armoury Crate",
    "jackettconsole.exe": "Jackett",
    "python.exe": "Python (this dashboard)",
    "svchost.exe": "Windows background services",
    "system": "Windows itself",
}

PARTIAL_RESULTS = False
_PUBLIC_NET_CACHE = {"ts": 0.0, "val": None, "has_val": False}

_PORT_RE = re.compile(r"\bports?\b\s*(?:number|#|;)?\s*(\d{2,5})", re.IGNORECASE)
_IP_RE = re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}\b")


def is_admin() -> bool:
    try:
        if os.name == "nt":
            return bool(ctypes.windll.shell32.IsUserAnAdmin())
        return os.geteuid() == 0
    except Exception as exc:
        logger.exception("is_admin check failed: %s", exc)
        return False


def on_public_network(ttl: float = 15.0):
    """Return True if on a public network, False if not, or None if unknown."""
    if os.name != "nt":
        return None
    now = time.monotonic()
    if _PUBLIC_NET_CACHE["has_val"] and (now - _PUBLIC_NET_CACHE["ts"]) < ttl:
        return _PUBLIC_NET_CACHE["val"]
    try:
        out = subprocess.run(
            ["powershell", "-NoProfile", "-Command", "(Get-NetConnectionProfile).NetworkCategory"],
            capture_output=True,
            text=True,
            timeout=8,
            creationflags=0x08000000,
        )
        if out.returncode != 0 or not out.stdout.strip():
            logger.warning("on_public_network returned code %s: %s", out.returncode, out.stderr.strip())
            res = None
        else:
            res = "Public" in out.stdout
    except Exception as exc:
        logger.exception("on_public_network check failed: %s", exc)
        res = None
    _PUBLIC_NET_CACHE["ts"] = now
    _PUBLIC_NET_CACHE["val"] = res
    _PUBLIC_NET_CACHE["has_val"] = True
    return res


def get_secrets_path() -> str:
    return os.path.join(os.path.dirname(os.path.abspath(__file__)), ".streamlit", "secrets.toml")


def get_api_key():
    """GROQ_API_KEY from the environment, else from .streamlit/secrets.toml next to this file."""
    env_key = os.environ.get("GROQ_API_KEY")
    if env_key:
        return env_key.strip()
    path = get_secrets_path()
    if not os.path.exists(path):
        return None
    try:
        import tomllib

        with open(path, "rb") as fh:
            key = tomllib.load(fh).get("GROQ_API_KEY")
        if key:
            return str(key).strip()
    except Exception as exc:
        logger.exception("Failed to parse %s: %s", path, exc)
    return None


def clear_api_key():
    """Remove GROQ_API_KEY from current process env and .streamlit/secrets.toml if present."""
    os.environ.pop("GROQ_API_KEY", None)
    path = get_secrets_path()
    if os.path.exists(path):
        try:
            with open(path, "r", encoding="utf-8") as fh:
                lines = [ln for ln in fh if not ln.strip().startswith("GROQ_API_KEY")]
            if lines:
                with open(path, "w", encoding="utf-8") as fh:
                    fh.writelines(lines)
            else:
                os.remove(path)
        except Exception as exc:
            logger.exception("Failed to clear key from %s: %s", path, exc)


def _process_info(pid, cache):
    if not pid:
        return "System / Unknown", ""
    if pid in cache:
        return cache[pid]
    name, exe = "Protected System Process (Run as Admin)", ""
    try:
        proc = psutil.Process(pid)
        name = proc.name()
        try:
            exe = proc.exe()
        except (psutil.AccessDenied, psutil.NoSuchProcess) as exc:
            logger.debug("Could not read exe path for pid %s: %s", pid, exc)
            exe = ""
    except (psutil.AccessDenied, psutil.NoSuchProcess) as exc:
        logger.debug("Could not inspect process pid %s: %s", pid, exc)
    cache[pid] = (name, exe)
    return cache[pid]


def collect_network_facts():
    global PARTIAL_RESULTS
    PARTIAL_RESULTS = False

    groups = {}
    cache = {}
    try:
        conns = psutil.net_connections(kind="tcp")
    except psutil.AccessDenied as exc:
        PARTIAL_RESULTS = True
        logger.exception("psutil.net_connections denied access: %s", exc)
        return []
    except Exception as exc:
        PARTIAL_RESULTS = True
        logger.exception("psutil.net_connections failed: %s", exc)
        return []

    for conn in conns:
        if conn.status != psutil.CONN_LISTEN or not conn.laddr:
            continue
        key = (conn.laddr.port, conn.pid)
        if key not in groups:
            name, exe = _process_info(conn.pid, cache)
            if not exe and not is_admin():
                PARTIAL_RESULTS = True
            groups[key] = {"ips": set(), "name": name, "exe": exe}
        groups[key]["ips"].add(conn.laddr.ip)

    public = on_public_network()
    if public is None:
        PARTIAL_RESULTS = True

    findings = []
    for (port, pid), g in groups.items():
        ips = sorted(g["ips"])
        non_loopback = [i for i in ips if i not in ("127.0.0.1", "::1")]
        chosen_ip = non_loopback[0] if non_loopback else ips[0]
        finding = _kb_analyze_port(port, g["name"], pid, chosen_ip, g["exe"])
        if finding:
            if finding.get("unknown") and not (g.get("exe") or "").strip():
                finding["exe_uninspected"] = True  # needs_attention() adds the plain-English note
            finding["bind_addresses"] = ips
            finding["public_network"] = public
            findings.append(finding)

    findings.sort(key=lambda f: (RISK_RANK[f["risk"]], f["exposure"] != "Network", f["port"]))
    logger.info("collect_network_facts completed: %d findings, partial=%s", len(findings), PARTIAL_RESULTS)
    return findings


def classify_alert(f):
    """None = normal, nothing to do. 'Medium' = worth a look. 'High' = act now."""
    if f.get("exposure") != "Network":
        return None  # only this PC itself can reach it
    port = f.get("port")
    exe = (f.get("exe") or "").strip()
    exe_lower = exe.lower()

    if port in WINDOWS_NORMAL_PORTS:
        if port in (139, 445):
            pub = f.get("public_network")
            # Fail closed: True or unknown (None) on file/network sharing ports is worth a look.
            return "Medium" if (pub is True or pub is None) else None
        return None

    if f.get("unknown"):
        if not exe:
            return "Medium"
        return "Medium" if any(h in exe_lower for h in RISKY_PATH_HINTS) else None

    return f["risk"] if f.get("risk") in ("High", "Medium") else None


def needs_attention(findings):
    out = []
    for f in findings:
        lvl = classify_alert(f)
        if lvl:
            item = dict(f, alert_level=lvl)
            if f.get("unknown") and not (f.get("exe") or "").strip():
                note = "We couldn't inspect this program — run as administrator for full results."
                if note.lower() not in (item.get("business_impact") or "").lower():
                    item["business_impact"] = f"{item.get('business_impact', '').strip()} {note}".strip()
            out.append(item)
    out.sort(key=lambda f: (RISK_RANK[f["alert_level"]], f["port"]))
    return out


def normal_app_names(findings, alerts):
    """Plain names of everything that was checked and is fine, for the 'checked and normal' list."""
    flagged = {(a["port"], a["pid"]) for a in alerts}
    names = []
    for f in findings:
        if (f["port"], f["pid"]) in flagged:
            continue
        if f.get("unknown"):
            name = FRIENDLY_APPS.get((f.get("process") or "").lower()) or f.get("process") or "Unknown program"
        else:
            name = f["plain_title"]
        if name not in names:
            names.append(name)
    return names


def rule_based_summary(attention):
    if not attention:
        return "Your computer looks normal. Nothing to do. You can close this app."
    top = attention[0]
    plain_name = top.get("plain_title") or top.get("process") or "a background program"
    what_it_is = (top.get("description") or "It is running a network service on your computer.").strip()
    if not what_it_is.endswith((".", "!", "?")):
        what_it_is += "."
    fix = (top.get("fix") or "Close the program if you do not recognize it and run a security scan.").strip()
    return (
        f"One thing on your computer needs your attention. It's {plain_name} — {what_it_is} "
        f"Here's how to fix it, it takes about 2 minutes: {fix} "
        "Everything else on your computer looks fine."
    )


def _contains_unapproved_values(text: str, allowed_ips, allowed_ports) -> str:
    ok_ips = set(allowed_ips)
    ok_ports = {str(p) for p in allowed_ports}
    for ip in _IP_RE.findall(text):
        if ip not in ok_ips:
            return f"unexpected IP {ip}"
    for port in _PORT_RE.findall(text):
        if port not in ok_ports:
            return f"unexpected port {port}"
    return ""


def groq_rewrite(
    user_prompt,
    allowed_ips=(),
    allowed_ports=(),
    system=(
        "You explain security findings in calm, jargon-free English for non-technical people. "
        "Tone: calm, reassuring, human. Answer the user's real question: 'Am I being hacked or spied on?' "
        "If the findings are minor, say so explicitly. Never alarm the reader. "
        "If nothing is wrong, say 'you're fine' or 'you're safe.' "
        "Use 3 to 5 short sentences. No bullet points. No markdown. "
        "No port numbers, no IP addresses, no technical jargon, no product names the user won't recognize."
    ),
):
    """Ask Groq to rewrite findings in plain English, then fact-check the answer.

    Returns (text, "Groq LLM (...) • Verified by Rule Engine") on success, or
    (None, label) where label explains why the rule-based text is used instead.
    """
    api_key = get_api_key()
    if not api_key:
        logger.info("Groq call skipped: no GROQ_API_KEY configured; falling back to rule engine.")
        return None, "Rule Engine (No GROQ_API_KEY set)"

    headers = {"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"}
    last_error = "unknown error"

    for model_id in GROQ_MODELS:
        payload = {
            "model": model_id,
            "messages": [{"role": "system", "content": system}, {"role": "user", "content": user_prompt}],
            "temperature": 0.0,
            "max_tokens": 1024,
            "reasoning_effort": "low",
        }
        try:
            logger.info("Calling Groq model %s", model_id)
            resp = requests.post(GROQ_BASE_URL, headers=headers, json=payload, timeout=30)
            if resp.status_code != 200:
                try:
                    detail = resp.json().get("error", {}).get("message", "")
                except ValueError:
                    detail = ""
                last_error = f"{model_id} -> {resp.status_code}: {detail}"[:200]
                logger.warning("Groq non-200 response: %s", last_error)
                continue

            choice = resp.json()["choices"][0]
            text = (choice["message"].get("content") or "").strip()
            if not text:
                last_error = f"{model_id} returned empty content (finish_reason={choice.get('finish_reason')})"
                logger.warning("Groq empty content: %s", last_error)
                continue

            violation = _contains_unapproved_values(text, allowed_ips, allowed_ports)
            if violation:
                last_error = f"{model_id} failed fact-check ({violation})"
                logger.warning("Groq output rejected by fact-check: %s", last_error)
                continue

            logger.info("Groq response accepted for model %s", model_id)
            return text, f"Groq LLM ({model_id}) • Verified by Rule Engine"
        except Exception as exc:
            last_error = f"{model_id}: {type(exc).__name__}: {exc}"[:200]
            logger.exception("Groq request exception for %s: %s", model_id, exc)

    logger.info("All Groq attempts fell back to rule engine: %s", last_error)
    return None, f"Rule Engine Fallback ({last_error})"


def generate_executive_summary(findings):
    attention = needs_attention(findings)
    if not attention:
        if PARTIAL_RESULTS:
            return (
                "We could not finish a full check of everything on your computer, so we cannot say all clear yet. "
                "You are likely fine, and running as administrator gives a complete check.",
                "Deterministic Rule Engine",
            )
        return (
            "Your computer looks normal. Nothing to do. You can close this app.",
            "Deterministic Rule Engine",
        )

    top = attention[:5]
    facts = "\n".join(
        f"- {f['plain_title']}: {f['alert_level']} risk. Action: {f['fix']}"
        for f in top
    )
    user_prompt = (
        "Findings from a Windows computer check:\n"
        f"{facts}\n\n"
        "Answer whether the user is being hacked or spied on in plain, calm everyday English.\n"
        "Rules:\n"
        "1. Use 3 to 5 short sentences. No bullet points. No markdown.\n"
        "2. If the findings are minor, say so explicitly and never alarm the reader.\n"
        "3. Do not mention port numbers, IP addresses, technical jargon, or product names the user won't recognize.\n"
        "4. End with one clear, calm next step."
    )

    system_prompt = (
        "You explain computer check results in calm, reassuring, plain English for non-technical people. "
        "Tone: calm, reassuring, human. Answer the user's real question: 'Am I being hacked or spied on?' "
        "If the findings are minor, say so explicitly. Never alarm the reader. "
        "If nothing is wrong, say 'you're fine' or 'you're safe.' "
        "Use 3 to 5 short sentences. No bullet points. No markdown. "
        "No port numbers, no IP addresses, no technical jargon, no product names the user won't recognize."
    )

    fallback = rule_based_summary(attention)
    text, label = groq_rewrite(
        user_prompt,
        allowed_ips=(),
        allowed_ports=(),
        system=system_prompt,
    )
    if text:
        return text, label
    logger.info("Using rule-based fallback summary (%s)", label)
    return fallback, label


def build_plain_report(report, scan_time):
    findings = report.get("findings", [])
    attention = needs_attention(findings)
    ts = scan_time or time.strftime("%Y-%m-%d %H:%M")
    short_ts = ts[:16]

    lines = [
        "=== AUDIT4ALL REPORT ===",
        f"Date: {short_ts}",
    ]

    if not attention and PARTIAL_RESULTS:
        lines.extend([
            "Result: CHECK INCOMPLETE (RUN AS ADMINISTRATOR FOR FULL RESULTS)",
            "",
            f"What we checked: {len(findings)} background connections (partial check).",
            "What we found: we could not inspect everything completely, so we cannot mark all clear.",
            "",
            "What to do: Right-click the app or batch file and choose 'Run as administrator', then run the check again.",
        ])
        return "\n".join(lines)

    if not attention:
        lines.extend([
            "Result: YOUR COMPUTER LOOKS NORMAL",
            "",
            f"What we checked: {len(findings)} background connections on your computer.",
            "What we found: nothing suspicious.",
        ])
        return "\n".join(lines)

    top = attention[0]
    plain_name = top.get("plain_title") or top.get("process") or "Background program"
    why = (top.get("business_impact") or top.get("description") or "A background service may be reachable on your network.").strip()
    if not why.endswith((".", "!", "?")):
        why += "."
    fix = (top.get("fix") or "Close the program if you do not recognize it and run a security scan.").strip()

    lines.extend([
        "Result: ONE THING NEEDS YOUR ATTENTION",
        f"What: {plain_name}",
        f"Why it matters: {why}",
        f"What to do: {fix}",
        "",
        "Nothing else on your computer looks suspicious.",
    ])
    return "\n".join(lines)


def build_json_report(report, scan_time, tool_name="AUDIT4ALL Hybrid Endpoint Auditor"):
    findings = report["findings"]
    payload = {
        "schema_version": "1.0",
        "tool": tool_name,
        "scan_timestamp": scan_time,
        "partial_results": PARTIAL_RESULTS,
        "metrics": {
            "total_ports": len(findings),
            "high_risks": sum(1 for f in findings if f["risk"] == "High"),
            "medium_risks": sum(1 for f in findings if f["risk"] == "Medium"),
            "low_risks": sum(1 for f in findings if f["risk"] == "Low"),
            "network_exposed": sum(1 for f in findings if f["exposure"] == "Network"),
            "local_only": sum(1 for f in findings if f["exposure"] == "Local only"),
        },
        "executive_summary": {
            "summary": report["summary"],
            "generated_by": report["summary_source"],
        },
        "findings": findings,
    }
    return json.dumps(payload, indent=2)
