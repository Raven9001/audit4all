import json
import logging
import os
from datetime import datetime
import streamlit as st

import backend
from backend import (
    build_json_report,
    build_plain_report,
    collect_network_facts,
    generate_executive_summary,
    get_api_key,
    is_admin,
    needs_attention,
    normal_app_names,
)

logger = logging.getLogger(__name__)

INTRO_PARAGRAPH = (
    "This app checks if anything on your computer is exposed to the internet — "
    "the way a stranger would see it. It takes about 10 seconds. Nothing leaves "
    "your computer unless you ask for an AI summary. Click below to start."
)


def render_friendly_error(plain_msg: str, tech_detail: str):
    st.error(plain_msg)
    if tech_detail:
        with st.expander("Technical details (for IT people)"):
            st.code(tech_detail, language="text")


def inject_dark_css():
    st.markdown(
        """
        <style>
        .stApp { background-color: #232a2e; color: #d6dee3; }
        header[data-testid="stHeader"] { background-color: #2f383e; border-bottom: 1px solid #101417; }
        h1, h2, h3, h4 { color: #d6dee3; letter-spacing: 0.01em; }
        h1 { border-bottom: 3px solid #ff9d1c; display: inline-block; padding-bottom: 4px; }
        div[data-testid="stMetric"] {
            background-color: #2b343a;
            border: 1px solid #101417;
            border-radius: 2px;
            padding: 12px 16px;
        }
        div[data-testid="stMetricLabel"] p { color: #8e9ca6; text-transform: uppercase; font-size: 0.72rem; letter-spacing: 0.08em; }
        div[data-testid="stMetricValue"] { font-family: Consolas, monospace; font-weight: 700; }
        .stButton > button {
            background-color: #ff9d1c; color: #17191b; border: 1px solid #b86e00;
            border-radius: 2px; font-weight: 700; letter-spacing: 0.05em; text-transform: uppercase;
        }
        .stButton > button:hover { background-color: #ffb54d; color: #17191b; border-color: #b86e00; }
        .stDownloadButton > button {
            background-color: #36424a; color: #d6dee3; border: 1px solid #44525b; border-radius: 2px;
        }
        .stDownloadButton > button:hover { background-color: #3a464e; color: #ffb54d; border-color: #ff9d1c; }
        div[data-testid="stExpander"] { background-color: #2b343a; border: 1px solid #101417; border-radius: 2px; }
        div[data-testid="stAlert"] { border-radius: 2px; }
        hr { border-color: #101417; }
        </style>
        """,
        unsafe_allow_html=True,
    )


st.set_page_config(page_title="AUDIT4ALL", page_icon="🛡️", layout="wide")
inject_dark_css()

st.title("🛡️ AUDIT4ALL")
st.caption("Am I being hacked or spied on? A calm check for your computer.")

admin = is_admin()
if not admin:
    st.warning("We couldn't check everything. For a full check, right-click the app and choose 'Run as administrator.'")

if not get_api_key():
    st.info(
        "AI summaries are off. The app still works — you'll get hand-written summaries instead. "
        "Click 'AI settings' to enable AI."
    )

with st.expander("AI settings (optional)"):
    st.write(
        "AI summaries are optional. Without a key, AUDIT4ALL gives you calm, hand-written summaries "
        "that never leave your computer."
    )
    key_input = st.text_input("AI key", type="password", placeholder="Paste key if you have one")
    if st.button("Save AI key"):
        cleaned = (key_input or "").strip()
        if not cleaned or any(ch in cleaned for ch in "\"\x27\r\n "):
            st.error("Please paste the key only, with no spaces or quotes.")
        else:
            os.environ["GROQ_API_KEY"] = cleaned
            st.success("AI key saved for this session.")

st.session_state.setdefault("started", False)
st.session_state.setdefault("report", None)
st.session_state.setdefault("report_json", None)
st.session_state.setdefault("report_txt", None)
st.session_state.setdefault("scan_time", None)

if not st.session_state.started and st.session_state.report is None:
    st.markdown(INTRO_PARAGRAPH)
    if st.button("Run audit"):
        st.session_state.started = True
        run_clicked = True
    else:
        run_clicked = False
else:
    run_clicked = st.button("Run audit")

if run_clicked:
    try:
        with st.status("Checking your computer...", expanded=False) as status:
            status.update(label="Checking background connections on this computer...")
            facts = collect_network_facts()
            scan_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            status.update(label="Writing your plain-English answer...")
            summary, source = generate_executive_summary(facts)
            status.update(label="Check complete.", state="complete")

        report_obj = {"summary": summary, "summary_source": source, "findings": facts}
        st.session_state.scan_time = scan_time
        st.session_state.report = report_obj
        st.session_state.report_json = build_json_report(report_obj, scan_time)
        st.session_state.report_txt = build_plain_report(report_obj, scan_time)
    except Exception as exc:
        logger.exception("Streamlit audit failed: %s", exc)
        render_friendly_error(
            "We couldn't complete this check right now. Try again, or run as administrator for a full check.",
            f"{type(exc).__name__}: {exc}",
        )

report = st.session_state.report
if report:
    findings = report["findings"]
    actionable = needs_attention(findings)

    st.download_button(
        label="Save a plain report (readable)",
        data=st.session_state.report_txt or build_plain_report(report, st.session_state.scan_time),
        file_name=f"audit4all_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt",
        mime="text/plain",
    )

    st.caption(f"Checked: {st.session_state.scan_time}")
    st.divider()

    m1, m2, m3 = st.columns(3)
    m1.metric("Checked", len(findings))
    m2.metric("To look at", len(actionable))
    m3.metric("Normal", len(findings) - len(actionable))

    st.divider()

    if not actionable and backend.PARTIAL_RESULTS:
        st.warning("Check was incomplete. Run as administrator for a full answer.")
    elif not actionable:
        st.success("Your computer looks normal. Nothing to do.")
    elif actionable[0]["alert_level"] == "High":
        st.error("Something needs your attention. Here's how to fix it.")
    else:
        st.warning("One thing to look at. It's probably fine. Here's how to check.")

    st.info(report["summary"])
    st.caption(f"Summary by: {report['summary_source']}")

    for f in actionable:
        header = (
            "Something needs your attention. Here's how to fix it. | " + f["plain_title"]
            if f["alert_level"] == "High"
            else "One thing to look at. It's probably fine. Here's how to check. | " + f["plain_title"]
        )
        with st.expander(header, expanded=True):
            st.markdown(f"**What's happening:** {f['description']}")
            st.markdown(f"**Why it matters:** {f['business_impact']}")
            st.markdown(f"**What to do:** {f['fix']}")

    normal = normal_app_names(findings, actionable)
    if normal:
        with st.expander(f"Checked and normal ({len(normal)})"):
            st.markdown("\n".join(f"- {n}" for n in normal))

    show_tech = st.checkbox("Show technical details (for IT people)", value=False)
    if show_tech:
        st.subheader("Technical details (for IT people)")
        for f in findings:
            with st.expander(f"{f['plain_title']} — {f['process']} (port {f['port']})"):
                st.json(f)
        st.download_button(
            label="Download technical report (.JSON)",
            data=st.session_state.report_json,
            file_name=f"audit4all_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json",
            mime="application/json",
        )


# ---------------------------------------------------------------------------
# NETWORK ACTIVITY CHECK
# ---------------------------------------------------------------------------
st.divider()
st.header("Network activity check")
st.caption(
    "Watches what your computer sends and receives for a short time to spot anything unusual. "
    "Only a short summary is ever sent if AI is turned on."
)
st.session_state.setdefault("pcap", None)

if not backend.PCAP_ANALYZER_OK:
    st.info(
        "To watch live network traffic, install Npcap from npcap.com (tick 'WinPcap API-compatible mode') "
        "and run as administrator."
    )
else:
    try:
        from pcap_analyzer import capture_live, explain_capture, list_interfaces
        pcap_imports_ok = True
    except ImportError as exc:
        logger.exception("Failed importing pcap_analyzer functions: %s", exc)
        pcap_imports_ok = False
        st.info(
            "To watch live network traffic, install Npcap from npcap.com (tick 'WinPcap API-compatible mode') "
            "and run as administrator."
        )

    if pcap_imports_ok:
        try:
            iface_map = list_interfaces()
        except Exception as exc:
            logger.exception("Failed listing network adapters: %s", exc)
            iface_map = {}

        cc1, cc2 = st.columns(2)
        with cc1:
            choice = st.selectbox(
                "Connection type",
                ["Default connection"] + list(iface_map),
                help="Pick the connection you use for the internet (such as Wi-Fi).",
            )
        with cc2:
            seconds = st.slider(
                "How long to watch (seconds)",
                10,
                300,
                60,
                step=10,
                help="Longer checks can spot repeating background activity.",
            )

        if st.button("Start activity check"):
            try:
                with st.spinner(f"Checking for {seconds} seconds... use your computer normally."):
                    result = capture_live(seconds, iface_map.get(choice))
                    summary, source = explain_capture(result)
                captured_at = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                payload_json = json.dumps(
                    {
                        "schema_version": "1.0",
                        "captured_at": captured_at,
                        "adapter": choice,
                        "summary": summary,
                        "engine": source,
                        **result,
                    },
                    indent=2,
                )
                st.session_state.pcap = {
                    "result": result,
                    "summary": summary,
                    "source": source,
                    "adapter": choice,
                    "seconds": seconds,
                    "captured_at": captured_at,
                    "payload_json": payload_json,
                }
            except Exception as exc:
                logger.exception("Live traffic check failed: %s", exc)
                render_friendly_error(
                    "To watch live network traffic, install Npcap from npcap.com (tick 'WinPcap API-compatible mode') and run as administrator.",
                    f"{type(exc).__name__}: {exc}",
                )

pcap = st.session_state.pcap
if pcap:
    result = pcap["result"]
    stats, pfindings = result["stats"], result["findings"]

    p1, p2, p3 = st.columns(3)
    p1.metric("Activity items", f"{stats['packets']:,}")
    p2.metric("Seconds", stats["duration_s"])
    p3.metric("To look at", len(pfindings))
    st.caption(f"Checked: {pcap['captured_at']} • Duration: {pcap['seconds']}s")

    if stats["packets"] == 0:
        st.warning("No activity was caught. Try another connection option, install Npcap from npcap.com, and run as administrator.")
    if stats["truncated"]:
        st.warning("This check hit its size limit and stopped early.")

    levels = {f["risk"] for f in pfindings}
    if "High" in levels:
        st.error("Something needs your attention. Here's how to fix it.")
    elif "Medium" in levels:
        st.warning("One thing to look at. It's probably fine. Here's how to check.")
    elif stats["packets"] > 0:
        st.success("Your computer looks normal. Nothing to do.")

    st.info(pcap["summary"])
    st.caption(f"Summary by: {pcap['source']}")

    for f in pfindings:
        with st.expander(f["title"], expanded=(f["risk"] == "High")):
            st.markdown(f"**What's happening:** {f['what']}")
            st.markdown(f"**Why it matters:** {f['why']}")
            st.markdown(f"**What to do:** {f['fix']}")

    show_pcap_tech = st.checkbox("Show technical details (for IT people)", value=False, key="pcap_tech_gate")
    if show_pcap_tech:
        st.write("Protocol mix:", stats["protocols"])
        st.write("Busy connections")
        st.dataframe(result["top_talkers"], use_container_width=True)
        st.write("Looked-up names")
        st.dataframe(result["top_dns"], use_container_width=True)
        st.download_button(
            "Download technical traffic report (.JSON)",
            data=pcap["payload_json"],
            file_name=f"audit4all_traffic_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json",
            mime="application/json",
        )
