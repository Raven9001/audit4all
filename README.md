<div align="center">

<img src="assets/banner.svg" alt="AUDIT4ALL - Am I being hacked or spied on?" width="100%">

<br><br>

<a href="https://github.com/Raven9001/audit4all/releases/latest"><img src="https://img.shields.io/badge/Windows-10%20%7C%2011-0078D6?style=for-the-badge&logo=windows&logoColor=white" alt="Windows"></a>
<a href="#"><img src="https://img.shields.io/badge/Python-3.9+-3776AB?style=for-the-badge&logo=python&logoColor=white" alt="Python"></a>
<a href="https://github.com/Raven9001/audit4all/releases/latest"><img src="https://img.shields.io/github/v/release/Raven9001/audit4all?style=for-the-badge&color=ff9d1c" alt="Release"></a>
<a href="LICENSE"><img src="https://img.shields.io/github/license/Raven9001/audit4all?style=for-the-badge&color=44525b" alt="License"></a>
<img src="https://img.shields.io/badge/runs-100%25%20offline-2e8b57?style=for-the-badge" alt="Offline">

<br><br>

<h3>A calm, plain-English security check for your Windows PC.</h3>

<a href="https://github.com/Raven9001/audit4all/releases/latest"><b>&#11015;&#65039; Download</b></a>
&nbsp;&nbsp;|&nbsp;&nbsp;
<a href="#-quick-start"><b>Quick start</b></a>
&nbsp;&nbsp;|&nbsp;&nbsp;
<a href="#-run-from-source"><b>Run from source</b></a>
&nbsp;&nbsp;|&nbsp;&nbsp;
<a href="https://github.com/Raven9001/audit4all/issues"><b>Report a bug</b></a>

</div>

<br>

<p align="center">
  <img src="assets/preview.svg" alt="Example AUDIT4ALL result" width="85%">
</p>
<p align="center"><sub>Illustration of the result format. Every finding answers three questions.</sub></p>

<br>

## Why this exists

AUDIT4ALL answers one question: **is anything on this computer exposed or behaving strangely, and what should I do about it?**

Every result comes with three lines: *what's happening*, *why it matters*, and *what to do*. Technical details are there if you want them, hidden if you don't.

<br>

## What it checks

<table>
  <tr>
    <td align="center" width="33%" valign="top">
      <h3>&#128682;<br>Open ports</h3>
      <p>Which programs are listening, and whether they can be reached from your network or only from your own PC.</p>
      <sub>psutil + a knowledge base of 40+ common ports (RDP, SMB, databases, dev servers, VNC)</sub>
    </td>
    <td align="center" width="33%" valign="top">
      <h3>&#9881;&#65039;<br>Startup programs</h3>
      <p>What launches by itself when Windows boots: unsigned entries, programs running from Temp or Downloads, hidden launch tricks.</p>
      <sub>Microsoft Autoruns, downloaded and signature-verified</sub>
    </td>
    <td align="center" width="33%" valign="top">
      <h3>&#128225;<br>Live traffic</h3>
      <p>A short capture of what your PC sends and receives: repeating check-ins, port scans, unencrypted logins, odd lookups.</p>
      <sub>scapy + Npcap</sub>
    </td>
  </tr>
</table>

<p align="center">
  Findings are ranked <b>High</b> / <b>Medium</b> / <b>Low</b>.<br>
  Anything normal is tucked into a "checked and normal" list so the screen stays quiet when there's nothing to worry about.
</p>

<br>

## Two ways to use it

<table>
  <tr>
    <td align="center" width="50%">
      <h3>&#128421;&#65039; Desktop app</h3>
      <p>Built with Tkinter.<br>Double-click and go.</p>
    </td>
    <td align="center" width="50%">
      <h3>&#127760; Browser app</h3>
      <p>Built with Streamlit.<br>Dark dashboard with downloadable reports.</p>
    </td>
  </tr>
</table>

<p align="center">Both start from the same <code>run_audit4all.bat</code>, which asks which one you want.<br>Reports save as a readable <code>.txt</code> or a full <code>.json</code>.</p>

<br>

## &#128640; Quick start

<table>
  <tr>
    <td width="60" align="center"><h2>1</h2></td>
    <td>Download the latest zip from <b><a href="https://github.com/Raven9001/audit4all/releases/latest">Releases</a></b> and extract it.</td>
  </tr>
  <tr>
    <td align="center"><h2>2</h2></td>
    <td>Double-click <b><code>run_audit4all.bat</code></b>.</td>
  </tr>
  <tr>
    <td align="center"><h2>3</h2></td>
    <td>Say <b>Yes</b> to the administrator prompt. Without it, Windows hides program paths and live capture won't work.</td>
  </tr>
  <tr>
    <td align="center"><h2>4</h2></td>
    <td>Pick Desktop or Browser, then press <b>Run audit</b>.</td>
  </tr>
</table>

> [!TIP]
> **SmartScreen warning?** Click *More info*, then *Run anyway*. The app is open source, so you can read every line before running it.

> [!NOTE]
> You only need [Python 3](https://www.python.org/downloads/) with **"Add python.exe to PATH"** ticked. The launcher installs everything else on first run.
> For live traffic, also install [Npcap](https://npcap.com) and tick **"WinPcap API-compatible mode"**.

<br>

## &#129302; Optional AI summaries

AUDIT4ALL works fully offline. Without a key, a built-in rule engine writes the summaries. If the AI call ever fails, the app silently falls back to it, so you always get an answer.

<details>
<summary><b>How to turn on AI summaries (free Groq key)</b></summary>
<br>

1. Get a free key at [console.groq.com](https://console.groq.com/).
2. **Browser app:** open the **AI settings** panel near the top and paste the key.
3. **Or** set it before launching:

```bat
set GROQ_API_KEY=your_key_here
```

</details>

<br>

## &#128274; Privacy

<table>
  <tr>
    <td align="center" width="25%"><h3>&#127968;</h3><b>Local</b><br><sub>Port, startup and packet checks run on your PC</sub></td>
    <td align="center" width="25%"><h3>&#128221;</h3><b>Text only</b><br><sub>With AI on, only a short description of findings is sent. Never packets or files</sub></td>
    <td align="center" width="25%"><h3>&#128683;</h3><b>No key, no upload</b><br><sub>Nothing leaves your computer</sub></td>
    <td align="center" width="25%"><h3>&#9989;</h3><b>Verified</b><br><sub>Autoruns is deleted if the Microsoft signature fails</sub></td>
  </tr>
</table>

<br>

## &#128736;&#65039; Run from source

```bash
git clone https://github.com/Raven9001/audit4all.git
cd audit4all
pip install -r requirements.txt
python audit4all.py              # desktop app
python -m streamlit run app.py   # browser app
```

<details>
<summary><b>Project layout</b></summary>

```
audit4all.py        Desktop app (Tkinter)
app.py              Browser app (Streamlit)
backend.py          Port scanning, report building, summaries
knowledge_base.py   Plain-English knowledge about common ports
startup_audit.py    Autoruns download, verification and scoring
pcap_analyzer.py    Live traffic capture and detection rules
run_audit4all.bat   One-click launcher
assets/             README images
```

</details>

<br>

## &#9888;&#65039; Honest limits

> [!WARNING]
> AUDIT4ALL is a **first look**, not antivirus. A clean result means nothing obviously wrong was found, not that your PC is guaranteed safe. If something is flagged High and you can't explain it, run a proper malware scan and, on a work machine, tell your IT team.

<br>

## Contributing

Bugs, ideas and new port entries for `knowledge_base.py` are welcome. Open an issue or a pull request.

<br>

<div align="center">
  <sub>Built by <a href="https://github.com/Raven9001">Raven9001</a></sub>
</div>
