"""
pcap_analyzer.py - watches live network traffic for a short time and flags unusual patterns.

Needs scapy (pip install scapy) and, on Windows, Npcap (https://npcap.com, tick "WinPcap API-compatible mode").
Only counts and summaries are kept - packet payloads are never stored or sent anywhere.

Public API (used by audit4all.py and app.py):
    list_interfaces()                          -> {"Friendly name": scapy-interface-id}
    capture_live(seconds, iface, ptr_lookup)   -> result dict (stats, findings, top_talkers, top_dns)
    explain_capture(result)                    -> (plain-English summary, source label)
"""
import ipaddress
import logging
import socket
import statistics
import time
from collections import Counter, defaultdict
from concurrent.futures import ThreadPoolExecutor

import psutil
from scapy.all import ARP, DNS, ICMP, IP, TCP, UDP, IPv6, sniff  # ImportError here = feature unavailable

logger = logging.getLogger(__name__)

MAX_PACKETS = 150_000

OWNERS = {
    "google.com": "Google", "googleusercontent.com": "Google", "gstatic.com": "Google",
    "googleapis.com": "Google", "youtube.com": "Google", "googlevideo.com": "Google", "1e100.net": "Google",
    "microsoft.com": "Microsoft", "windows.com": "Microsoft", "windowsupdate.com": "Microsoft",
    "msedge.net": "Microsoft", "live.com": "Microsoft", "office.com": "Microsoft", "office.net": "Microsoft",
    "azure.com": "Microsoft", "azureedge.net": "Microsoft", "bing.com": "Microsoft", "msn.com": "Microsoft",
    "amazonaws.com": "Amazon", "cloudfront.net": "Amazon", "amazon.com": "Amazon",
    "cloudflare.com": "Cloudflare", "cloudflare.net": "Cloudflare",
    "akamai.net": "Akamai", "akamaiedge.net": "Akamai", "akamaitechnologies.com": "Akamai",
    "facebook.com": "Meta", "fbcdn.net": "Meta", "whatsapp.net": "Meta", "instagram.com": "Meta",
    "apple.com": "Apple", "icloud.com": "Apple", "mzstatic.com": "Apple",
    "spotify.com": "Spotify", "scdn.co": "Spotify", "spotifycdn.com": "Spotify",
    "discord.com": "Discord", "discordapp.com": "Discord", "discord.gg": "Discord",
    "steampowered.com": "Valve", "steamcontent.com": "Valve", "steamstatic.com": "Valve",
    "github.com": "GitHub", "githubusercontent.com": "GitHub",
    "mozilla.com": "Mozilla", "mozilla.org": "Mozilla", "mozilla.net": "Mozilla", "firefox.com": "Mozilla",
    "fastly.net": "Fastly", "twitch.tv": "Twitch", "ttvnw.net": "Twitch",
    "netflix.com": "Netflix", "nflxvideo.net": "Netflix", "groq.com": "Groq", "anthropic.com": "Anthropic",
    "vivaldi.com": "Vivaldi", "tiktok.com": "TikTok", "tiktokcdn.com": "TikTok",
}

CLEARTEXT_PORTS = {21: "FTP", 23: "Telnet", 25: "SMTP", 110: "POP3", 143: "IMAP"}
# port -> (name, risk)
SUSPICIOUS_PORTS = {
    4444: ("a port used by hacking tools", "High"), 31337: ("a classic backdoor port", "High"),
    12345: ("a port used by old remote-access trojans", "High"), 1337: ("a port often used by hacking tools", "Medium"),
    6667: ("IRC chat, sometimes used to control infected PCs", "Medium"),
    6697: ("IRC chat, sometimes used to control infected PCs", "Medium"),
    9001: ("the Tor anonymity network", "Medium"), 9030: ("the Tor anonymity network", "Medium"),
}

SYN, ACK = 0x02, 0x10
SECOND_LEVEL = {"co", "com", "org", "net", "gov", "ac", "edu"}


# --------------------------------------------------------------------------- helpers
def _is_public(ip):
    try:
        return ipaddress.ip_address(ip).is_global
    except ValueError:
        return False


def _local_ips():
    ips = set()
    try:
        for addrs in psutil.net_if_addrs().values():
            for a in addrs:
                if a.family in (socket.AF_INET, socket.AF_INET6):
                    ips.add(a.address.split("%")[0])
    except Exception as exc:
        logger.warning("Could not read local addresses: %s", exc)
    return ips


def _owner_for(name):
    name = (name or "").lower().rstrip(".")
    parts = name.split(".")
    for i in range(len(parts) - 1):
        suffix = ".".join(parts[i:])
        if suffix in OWNERS:
            return OWNERS[suffix]
    return ""


def _parent_domain(name):
    parts = name.lower().rstrip(".").split(".")
    if len(parts) < 2:
        return name
    if len(parts) >= 3 and len(parts[-1]) == 2 and parts[-2] in SECOND_LEVEL:
        return ".".join(parts[-3:])
    return ".".join(parts[-2:])


def list_interfaces():
    """Friendly adapter name -> the id scapy needs."""
    mapping = {}
    try:
        from scapy.arch.windows import get_windows_if_list  # only exists on Windows builds of scapy
        for ifc in get_windows_if_list():
            label = ifc.get("description") or ifc.get("name")
            ident = ifc.get("name") or ifc.get("description")
            if label and ident and ifc.get("ips"):
                mapping[label] = ident
    except Exception as exc:
        logger.debug("Windows adapter listing unavailable (%s); using generic list.", exc)
    if not mapping:
        try:
            from scapy.all import get_if_list
            mapping = {name: name for name in get_if_list()}
        except Exception as exc:
            logger.warning("Could not list adapters: %s", exc)
    return mapping


# --------------------------------------------------------------------------- collection
class Collector:
    """Turns a stream of simple packet records into counts. Fully testable without scapy."""

    def __init__(self, local_ips):
        self.local = set(local_ips)
        self.packets = 0
        self.bytes = 0
        self.protocols = Counter()
        self.convos = defaultdict(lambda: {"out": 0, "in": 0})   # (me, remote) -> bytes
        self.dns_counts = Counter()
        self.dns_subs = defaultdict(set)
        self.ip_names = {}
        self.new_conns = defaultdict(list)       # (remote, port) -> [timestamps of connections we opened]
        self.inbound_syn = defaultdict(set)      # public remote -> {our ports it tried}
        self.arp_macs = defaultdict(set)         # ip -> {mac} seen in ARP replies
        self.cleartext = Counter()               # (service, remote) -> packets
        self.sus_ports = Counter()               # (remote, port) -> packets

    def add(self, rec):
        self.packets += 1
        size = rec.get("size", 0)
        self.bytes += size
        self.protocols[rec.get("proto", "Other")] += 1

        arp = rec.get("arp")
        if arp:
            ip, mac, op = arp
            if op == 2 and mac and mac.lower() != "ff:ff:ff:ff:ff:ff" and ip not in ("0.0.0.0", ""):
                self.arp_macs[ip].add(mac.lower())
            return

        src, dst = rec.get("src"), rec.get("dst")
        if not src or not dst:
            return
        src_me, dst_me = src in self.local, dst in self.local
        if src_me != dst_me:
            me, remote = (src, dst) if src_me else (dst, src)
            self.convos[(me, remote)]["out" if src_me else "in"] += size

        dns = rec.get("dns")
        if dns:
            q = dns.get("query")
            if q:
                self.dns_counts[q] += 1
                self.dns_subs[_parent_domain(q)].add(q)
            for name, ip in dns.get("answers", ()):
                self.ip_names.setdefault(ip, name)

        flags, dport, sport = rec.get("flags"), rec.get("dport"), rec.get("sport")
        if rec.get("proto") in ("TCP", "DNS") and flags is not None and (flags & SYN) and not (flags & ACK):
            if src_me and not dst_me and dport:
                bucket = self.new_conns[(dst, dport)]
                if len(bucket) < 300:
                    bucket.append(rec.get("t", 0.0))
            elif dst_me and not src_me and _is_public(src) and dport:
                self.inbound_syn[src].add(dport)

        remote_port = dport if (src_me and not dst_me) else None
        remote_ip = dst if remote_port else None
        if remote_port and _is_public(remote_ip):
            if remote_port in CLEARTEXT_PORTS:
                self.cleartext[(CLEARTEXT_PORTS[remote_port], remote_ip)] += 1
            if remote_port in SUSPICIOUS_PORTS:
                self.sus_ports[(remote_ip, remote_port)] += 1

    # ---- results
    def name_of(self, ip, ptr=None):
        return self.ip_names.get(ip) or (ptr or {}).get(ip) or ""

    def top_talkers(self, ptr=None, limit=10):
        rows = []
        for (me, remote), b in self.convos.items():
            total = b["out"] + b["in"]
            name = self.name_of(remote, ptr)
            rows.append({
                "src": me, "dst": remote, "src_is_me": True, "dst_is_me": False,
                "name": name, "owner": _owner_for(name),
                "megabytes": round(total / 1e6, 2), "_total": total,
            })
        rows.sort(key=lambda r: -r["_total"])
        for r in rows:
            r.pop("_total")
        return rows[:limit]

    def findings(self, ptr=None):
        out = []

        for ip, macs in self.arp_macs.items():
            if len(macs) > 1:
                out.append(_finding(
                    "High", "Two devices claim the same network address",
                    f"Two different devices both said they are {ip} on your network.",
                    "This can be a harmless setup mix-up, but it is also how someone on the same Wi-Fi "
                    "intercepts other people's traffic (called ARP spoofing).",
                    "If you are on public Wi-Fi, disconnect and use another network or your phone's hotspot. "
                    "At home, restart your router and check for unfamiliar devices.",
                    [f"Address: {ip}"] + [f"Seen as: {m}" for m in sorted(macs)]))

        for (remote, port), n in self.sus_ports.most_common(3):
            what_is, risk = SUSPICIOUS_PORTS[port]
            name = self.name_of(remote, ptr)
            out.append(_finding(
                risk, "Connection to an unusual port",
                f"Your computer connected to {name or remote} on port {port}, {what_is}.",
                "Honest programs rarely use this. Some infected computers use it to talk to their controller.",
                "Open Task Manager > Details, find what is using the network, and run a malware scan "
                "(Windows Security > Full scan).",
                [f"To: {remote}" + (f" ({name})" if name else ""), f"Port: {port}", f"Packets: {n}"]))

        for (svc, remote), n in self.cleartext.most_common(3):
            name = self.name_of(remote, ptr)
            out.append(_finding(
                "Medium", f"Unencrypted {svc} connection",
                f"Your computer talked to {name or remote} using {svc}, which is not encrypted.",
                "Anything sent this way, including passwords, can be read by others on the path.",
                "Use the encrypted version (SFTP, IMAPS, POP3S, or HTTPS) and avoid doing this on public Wi-Fi.",
                [f"To: {remote}" + (f" ({name})" if name else ""), f"Service: {svc}", f"Packets: {n}"]))

        for remote, ports in sorted(self.inbound_syn.items(), key=lambda kv: -len(kv[1]))[:2]:
            if len(ports) >= 15:
                out.append(_finding(
                    "High" if len(ports) >= 60 else "Medium", "Someone is probing your computer",
                    f"A device on the internet tried {len(ports)} different doors (ports) on your computer in a short time.",
                    "This is called a port scan. It is very common on the internet, and it is only a problem "
                    "if something on your computer answers.",
                    "Keep Windows Firewall on, and avoid public Wi-Fi without it. Run the Home check to see what is reachable.",
                    [f"From: {remote}", f"Ports tried: {len(ports)}"]))

        for parent, subs in sorted(self.dns_subs.items(), key=lambda kv: -len(kv[1]))[:2]:
            if len(subs) < 40 or parent.endswith((".arpa", ".local")):
                continue
            avg = statistics.mean(len(s.split(".")[0]) for s in subs)
            if avg >= 20:
                out.append(_finding(
                    "Medium", "Unusual pattern of name lookups",
                    f"Your computer looked up {len(subs)} different long, random-looking names under {parent}.",
                    "Some malware hides data inside name lookups (DNS tunneling). Some security and "
                    "sync software also behaves like this, so it is usually harmless.",
                    "If you do not recognize the website, run a malware scan.",
                    [f"Domain: {parent}", f"Different names: {len(subs)}", f"Average length: {avg:.0f} characters"]))

        beacons = []
        for (remote, port), times in self.new_conns.items():
            if len(times) >= 8:
                gaps = [b - a for a, b in zip(times, times[1:]) if b > a]
                if len(gaps) >= 7:
                    mean = statistics.mean(gaps)
                    if 3 <= mean <= 120 and statistics.pstdev(gaps) / mean < 0.1:
                        beacons.append((len(times), remote, port, mean))
        for n, remote, port, mean in sorted(beacons, reverse=True)[:2]:
            name = self.name_of(remote, ptr)
            out.append(_finding(
                "Medium", "Something checks in on a strict schedule",
                f"A program opened a new connection to {name or remote} about every {mean:.0f} seconds, {n} times.",
                "Regular check-ins are normal for update checkers and chat apps. Malware also does this to "
                "wait for instructions, so it is worth knowing what it is.",
                "Look at Task Manager > Performance > Open Resource Monitor > Network to see which program it is.",
                [f"To: {remote}:{port}" + (f" ({name})" if name else ""), f"Connections: {n}", f"Every ~{mean:.0f} s"]))

        for (me, remote), b in sorted(self.convos.items(), key=lambda kv: -kv[1]["out"])[:1]:
            if b["out"] >= 25e6 and b["out"] >= 8 * max(b["in"], 1):
                name = self.name_of(remote, ptr)
                out.append(_finding(
                    "Medium", "Large upload to one address",
                    f"Your computer sent about {b['out'] / 1e6:.0f} MB to {name or remote} and received very little back.",
                    "Uploads like this are normal for cloud backups, photo sync, video calls and game updates. "
                    "They are also how stolen data leaves a computer.",
                    "If you were not backing up or uploading something, open Task Manager > Processes and sort by Network.",
                    [f"To: {remote}" + (f" ({name})" if name else ""), f"Sent: {b['out'] / 1e6:.1f} MB",
                     f"Received: {b['in'] / 1e6:.1f} MB"]))

        out.sort(key=lambda f: 0 if f["risk"] == "High" else 1)
        return out


def _finding(risk, title, what, why, fix, evidence):
    return {"risk": risk, "title": title, "what": what, "why": why, "fix": fix, "evidence": list(evidence)}


def _lookup_names(ips):
    """Optional reverse-DNS for the busiest unknown addresses (asks your DNS server, so it is opt-in)."""
    found = {}
    if not ips:
        return found

    def one(ip):
        try:
            return socket.gethostbyaddr(ip)[0]
        except Exception:
            return ""

    with ThreadPoolExecutor(max_workers=8) as pool:
        futures = {ip: pool.submit(one, ip) for ip in ips}
        for ip, fut in futures.items():
            try:
                name = fut.result(timeout=3)
                if name:
                    found[ip] = name
            except Exception:
                continue
    return found


def build_result(col, duration, truncated, ptr_lookup=False):
    ptr = None
    if ptr_lookup:
        unknown = [r["dst"] for r in col.top_talkers(limit=10) if not r["name"]]
        ptr = _lookup_names(unknown)
    return {
        "stats": {
            "packets": col.packets,
            "duration_s": round(duration, 1),
            "truncated": truncated,
            "protocols": dict(col.protocols.most_common()),
            "bytes": col.bytes,
        },
        "findings": col.findings(ptr),
        "top_talkers": col.top_talkers(ptr),
        "top_dns": [{"name": n, "count": c} for n, c in col.dns_counts.most_common(10)],
    }


# --------------------------------------------------------------------------- scapy glue
def _extract(pkt):
    """Reduce one scapy packet to a small dict (no payload is kept)."""
    rec = {"t": float(pkt.time), "size": len(pkt), "proto": "Other"}
    if ARP in pkt:
        a = pkt[ARP]
        rec["proto"] = "ARP"
        rec["arp"] = (a.psrc, a.hwsrc, int(a.op))
        return rec
    if IP in pkt:
        rec["src"], rec["dst"] = pkt[IP].src, pkt[IP].dst
    elif IPv6 in pkt:
        rec["src"], rec["dst"] = pkt[IPv6].src, pkt[IPv6].dst
    else:
        return rec
    if TCP in pkt:
        t = pkt[TCP]
        rec.update(proto="TCP", sport=int(t.sport), dport=int(t.dport), flags=int(t.flags))
    elif UDP in pkt:
        u = pkt[UDP]
        rec.update(proto="UDP", sport=int(u.sport), dport=int(u.dport))
    elif ICMP in pkt:
        rec["proto"] = "ICMP"
    if pkt.haslayer(DNS) and 53 in (rec.get("sport"), rec.get("dport")):
        rec["proto"] = "DNS"
        dns = pkt[DNS]
        info = {"answers": []}
        try:
            if dns.qr == 0 and dns.qd is not None:
                qn = dns.qd.qname
                info["query"] = (qn.decode(errors="replace") if isinstance(qn, bytes) else str(qn)).rstrip(".")
            elif dns.qr == 1:
                for i in range(int(dns.ancount or 0)):
                    rr = dns.an[i]
                    if int(rr.type) in (1, 28):
                        rn = rr.rrname.decode(errors="replace") if isinstance(rr.rrname, bytes) else str(rr.rrname)
                        info["answers"].append((rn.rstrip("."), str(rr.rdata)))
        except Exception as exc:
            logger.debug("DNS decode skipped: %s", exc)
        rec["dns"] = info
    return rec


def capture_live(seconds, iface=None, ptr_lookup=False):
    col = Collector(_local_ips())

    def handle(pkt):
        try:
            col.add(_extract(pkt))
        except Exception as exc:
            logger.debug("Packet skipped: %s", exc)

    started = time.time()
    sniff(iface=iface, prn=handle, store=False, timeout=seconds,
          stop_filter=lambda _p: col.packets >= MAX_PACKETS)
    return build_result(col, time.time() - started, col.packets >= MAX_PACKETS, ptr_lookup)


# --------------------------------------------------------------------------- plain-English summary
def _rule_summary(result):
    stats, findings = result["stats"], result["findings"]
    if stats["packets"] == 0:
        return ("We could not see any network activity. Try a different connection type, make sure Npcap is "
                "installed, and run the app as administrator.")
    if not findings:
        return "Your network activity looks normal during this check. Nothing stood out. You're fine."
    top = findings[0]
    extra = len(findings) - 1
    more = f" {extra} other minor thing{'s' if extra != 1 else ''} also showed up." if extra else ""
    return f"One thing stood out: {top['title'].lower()}. {top['fix']}{more} Everything else looked normal."


def explain_capture(result):
    findings = result["findings"]
    fallback = _rule_summary(result)
    if not findings or result["stats"]["packets"] == 0:
        return fallback, "Deterministic Rule Engine"
    try:
        from backend import groq_rewrite
    except ImportError:
        return fallback, "Deterministic Rule Engine"
    facts = "\n".join(f"- {f['title']}: {f['risk']} risk. Action: {f['fix']}" for f in findings[:5])
    prompt = (
        "Findings from watching a Windows computer's network activity:\n"
        f"{facts}\n\n"
        "Answer whether the user is being hacked or spied on in plain, calm everyday English.\n"
        "Rules:\n1. Use 3 to 5 short sentences. No bullet points. No markdown.\n"
        "2. If the findings are minor, say so explicitly and never alarm the reader.\n"
        "3. Do not mention port numbers, IP addresses, technical jargon, or product names the user won't recognize.\n"
        "4. End with one clear, calm next step."
    )
    text, label = groq_rewrite(prompt, allowed_ips=(), allowed_ports=())
    return (text, label) if text else (fallback, label)
