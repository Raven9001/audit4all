<div align="center">

# 🛡️ AUDIT4ALL

### *Am I being hacked or spied on?*
A calm, plain-English security check for your Windows PC.

<br>

[![Platform](https://img.shields.io/badge/Windows-10%20%7C%2011-0078D6?style=for-the-badge&logo=windows&logoColor=white)](#)
[![Python](https://img.shields.io/badge/Python-3.9+-3776AB?style=for-the-badge&logo=python&logoColor=white)](#)
[![Release](https://img.shields.io/github/v/release/Raven9001/audit4all?style=for-the-badge&color=ff9d1c)](https://github.com/Raven9001/audit4all/releases/latest)
[![License](https://img.shields.io/github/license/Raven9001/audit4all?style=for-the-badge&color=44525b)](LICENSE)

<br>

**[⬇️ Download for Windows](https://github.com/Raven9001/audit4all/releases/latest)**  ·  **[Run from source](#-run-from-source)**  ·  **[Report a bug](https://github.com/Raven9001/audit4all/issues)**

</div>

---

## Why this exists

Most security tools talk to you like you already work in IT. Port 3389 is open, a service is bound to 0.0.0.0, something is beaconing to an unknown host. Great, but is that bad?

AUDIT4ALL answers one question: **is anything on this computer exposed or behaving strangely, and what should I do about it?** Every result comes with three lines: *what's happening*, *why it matters*, and *what to do*. Technical details are there if you want them, hidden if you don't.

---

## What it checks

| Check | What it looks at | How |
|---|---|---|
| **Open ports** | Which programs are listening, and whether they're reachable from your network or only from your own PC | `psutil` plus a built-in knowledge base of 40+ well-known ports (RDP, SMB, databases, dev servers, VNC, and more) |
| **Startup programs** | What launches by itself when Windows boots: unsigned entries, programs running from Temp/Downloads, hidden PowerShell or `mshta` launch strings | Microsoft's official [Autoruns](https://learn.microsoft.com/sysinternals/downloads/autoruns), downloaded and signature-verified |
| **Live traffic** | A short capture of what your PC sends and receives: repeating check-ins, port scans, unencrypted logins, odd DNS lookups | `scapy` + Npcap |

Findings are ranked **High / Medium / Low**. Anything normal is tucked into a "checked and normal" list so the screen stays quiet when there's nothing to worry about.

---

## Two ways to use it

**Desktop app** (Tkinter): double-click and go.
**Browser app** (Streamlit): same checks, with a dark dashboard and downloadable reports.

Both are launched from the same `run_audit4all.bat`, which asks which one you want.

Reports can be saved as a readable `.txt` or a full `.json`.

---

## 🚀 Quick start

1. Download the latest zip from **[Releases](https://github.com/Raven9001/audit4all/releases/latest)** and extract it.
2. Double-click **`run_audit4all.bat`**.
3. Say **Yes** to the administrator prompt. Without it, Windows hides program paths and live capture won't work.
4. Pick Desktop or Browser, then hit **Run audit**.

> **SmartScreen warning?** Click *More info → Run anyway*. The app is open source, so you can read every line before running it.

The launcher installs the Python packages it needs on first run. You only need [Python 3](https://www.python.org/downloads/) installed, with **"Add python.exe to PATH"** ticked.

**For live traffic**, install [Npcap](https://npcap.com) and tick *"WinPcap API-compatible mode"* during setup.

---

## 🤖 Optional AI summaries

AUDIT4ALL works fully offline. Without a key, a built-in rule engine writes the summaries.

If you want a more natural-sounding summary, add a free [Groq](https://console.groq.com/) API key:

- **Browser app:** open the **AI settings** panel near the top and paste your key.
- **Or** set it yourself before launching:
  ```bat
  set GROQ_API_KEY=your_key_here
  ```

If the AI call fails for any reason, the app silently falls back to the rule engine. You always get an answer.

---

## 🔒 Privacy

- Port checks, startup checks and packet analysis all run **locally**.
- If AI summaries are on, only a short text description of the findings is sent. **Never** raw packets, file contents or your files.
- With no key set, **nothing leaves your computer.**
- The only thing the app downloads on its own is Autoruns from `download.sysinternals.com`, and it deletes the files again if the Microsoft signature doesn't verify.

---

## 🛠️ Run from source

```bash
git clone https://github.com/Raven9001/audit4all.git
cd audit4all
pip install -r requirements.txt
python audit4all.py          # desktop app
python -m streamlit run app.py   # browser app
```

### Project layout

```
audit4all.py        Desktop app (Tkinter)
app.py              Browser app (Streamlit)
backend.py          Port scanning, report building, summaries
knowledge_base.py   Plain-English knowledge about common ports
startup_audit.py    Autoruns download, verification and scoring
pcap_analyzer.py    Live traffic capture and detection rules
run_audit4all.bat   One-click launcher
```

---

## ⚠️ Honest limits

AUDIT4ALL is a **first look**, not antivirus. A clean result means nothing obviously wrong was found, not that your PC is guaranteed safe. If something is flagged High and you can't explain it, run a proper malware scan and, if it's a work machine, tell your IT team.

---

## Contributing

Bugs, ideas and new port entries for `knowledge_base.py` are welcome. Open an issue or a pull request.

## License

Add a `LICENSE` file (MIT is a good default) and this section will match the badge above.

<div align="center">
<sub>Built by <a href="https://github.com/Raven9001">Raven9001</a></sub>
</div>
