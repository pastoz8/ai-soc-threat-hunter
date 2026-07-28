import os
import json
import re
import sqlite3
import shutil
import httpx
from dotenv import load_dotenv
from openai import OpenAI
import streamlit as st
import pandas as pd
import numpy as np
from sklearn.ensemble import IsolationForest
import pydeck as pdk
import plotly.express as px
from datetime import datetime

load_dotenv()
client = OpenAI()

st.set_page_config(
    page_title="ApexSOC | Enterprise Threat Hunter & SOAR", 
    page_icon="🛡️", 
    layout="wide",
    initial_sidebar_state="expanded"
)

# --- HIGH-CONTRAST ENTERPRISE CYBERSECURITY UI & EXECUTIVE CSS ---
st.markdown("""
<style>
    @import url('https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&family=JetBrains+Mono:wght@400;500;700&display=swap');

    /* Global Theme & High-Contrast Readability */
    .stApp {
        background: #070b14;
        color: #e2e8f0;
        font-family: 'Inter', sans-serif;
    }
    
    /* Monospace elements */
    code, pre, .stCodeBlock, [data-testid="stCode"] {
        font-family: 'JetBrains Mono', monospace !important;
        background-color: #020617 !important;
        color: #38bdf8 !important;
        border: 1px solid #334155 !important;
        border-radius: 6px !important;
    }
    
    /* Sidebar Styling */
    [data-testid="stSidebar"] {
        background-color: #050811;
        border-right: 1px solid #1e293b;
    }
    [data-testid="stSidebar"] p, [data-testid="stSidebar"] span, [data-testid="stSidebar"] label {
        color: #cbd5e1 !important;
    }
    
    /* Headers - Maximum Contrast White */
    h1, h2, h3, h4, h5, h6 {
        color: #ffffff !important;
        font-family: 'Inter', sans-serif;
        font-weight: 600;
        letter-spacing: -0.025em;
    }
    
    /* --- HIGH-CONTRAST DARK MODE INPUTS & TEXT BOXES --- */
    [data-testid="stTextInput"] input, 
    [data-testid="stTextArea"] textarea {
        background-color: #020617 !important;
        color: #ffffff !important;
        border: 1px solid #475569 !important;
        border-radius: 8px !important;
        font-family: 'Inter', sans-serif !important;
        font-size: 0.95rem !important;
        box-shadow: inset 0 2px 4px rgba(0, 0, 0, 0.5);
    }
    [data-testid="stTextInput"] input:focus, 
    [data-testid="stTextArea"] textarea:focus {
        border-color: #38bdf8 !important;
        box-shadow: 0 0 12px rgba(56, 189, 248, 0.35), inset 0 2px 4px rgba(0, 0, 0, 0.5) !important;
    }
    
    /* Input Labels Readability */
    [data-testid="stTextInput"] label, 
    [data-testid="stTextArea"] label,
    [data-testid="stSelectbox"] label,
    [data-testid="stFileUploader"] label {
        color: #f8fafc !important;
        font-weight: 500 !important;
    }
    
    /* Dropdown / Selectbox Styling */
    [data-testid="stSelectbox"] div[data-baseweb="select"] {
        background-color: #020617 !important;
        color: #ffffff !important;
        border: 1px solid #475569 !important;
        border-radius: 8px !important;
    }
    
    /* Executive Glassmorphic Panel Cards */
    .soc-panel {
        background: rgba(15, 23, 42, 0.95);
        backdrop-filter: blur(12px);
        -webkit-backdrop-filter: blur(12px);
        border: 1px solid #334155;
        border-left: 4px solid #0ea5e9;
        border-radius: 10px;
        padding: 22px;
        box-shadow: 0 10px 25px -5px rgba(0, 0, 0, 0.7);
        margin-bottom: 20px;
    }
    
    /* Tactical Primary Action Buttons */
    .stButton>button {
        width: 100%;
        border-radius: 8px;
        font-weight: 600;
        font-family: 'Inter', sans-serif;
        background: linear-gradient(135deg, #0ea5e9 0%, #2563eb 100%);
        color: #ffffff;
        border: 1px solid rgba(56, 189, 248, 0.5);
        padding: 0.6rem 1.2rem;
        box-shadow: 0 4px 14px rgba(14, 165, 233, 0.3);
        transition: all 0.2s ease-in-out;
    }
    .stButton>button:hover {
        background: linear-gradient(135deg, #0284c7 0%, #1d4ed8 100%);
        border-color: rgba(56, 189, 248, 0.9);
        box-shadow: 0 0 20px rgba(56, 189, 248, 0.5);
        transform: translateY(-1px);
    }
    
    /* Secondary / Purge Button Styling */
    button[kind="secondary"] {
        background: linear-gradient(135deg, #1e293b 0%, #0f172a 100%) !important;
        border: 1px solid rgba(239, 68, 68, 0.5) !important;
        color: #fca5a5 !important;
    }
    button[kind="secondary"]:hover {
        background: linear-gradient(135deg, #991b1b 0%, #7f1d1d 100%) !important;
        border-color: rgba(239, 68, 68, 0.9) !important;
        box-shadow: 0 0 18px rgba(239, 68, 68, 0.5) !important;
    }

    /* Executive Metric Indicator Cards */
    [data-testid="stMetric"] {
        background: rgba(15, 23, 42, 0.95);
        border: 1px solid #334155;
        padding: 16px;
        border-radius: 10px;
        box-shadow: 0 4px 8px -1px rgba(0, 0, 0, 0.4);
    }
    [data-testid="stMetricValue"] {
        color: #38bdf8 !important;
        font-family: 'JetBrains Mono', monospace !important;
        font-weight: 700;
        font-size: 1.7rem !important;
    }
    [data-testid="stMetricLabel"] {
        color: #e2e8f0 !important;
        font-weight: 600 !important;
        font-size: 0.9rem !important;
    }
    
    /* Dataframes Readability */
    [data-testid="stDataFrame"] {
        border-radius: 8px;
        overflow: hidden;
        border: 1px solid #334155;
    }
</style>
""", unsafe_allow_html=True)

# --- AUTHENTICATION STATE SETUP ---
if "authenticated" not in st.session_state:
    st.session_state.authenticated = False
if "username" not in st.session_state:
    st.session_state.username = ""
if "role" not in st.session_state:
    st.session_state.role = ""

# --- LOGIN SCREEN IF NOT AUTHENTICATED ---
if not st.session_state.authenticated:
    col1, col2, col3 = st.columns([1, 1.2, 1])
    with col2:
        st.markdown("<br><br>", unsafe_allow_html=True)
        st.markdown("""
        <div class="soc-panel" style="text-align: center; border-left: 4px solid #38bdf8;">
            <h2 style='color: #ffffff; margin-bottom: 5px; font-weight: 700;'>🛡️ ApexSOC Portal</h2>
            <p style='color: #cbd5e1; font-size: 0.95rem; margin-bottom: 25px;'>Enterprise Security Operations & Threat Intelligence Command</p>
        </div>
        """, unsafe_allow_html=True)
        
        with st.form("login_form"):
            username_input = st.text_input("Username")
            password_input = st.text_input("Password", type="password")
            st.markdown("<div style='height: 10px;'></div>", unsafe_allow_html=True)
            submit_login = st.form_submit_button("Authenticate & Enter", use_container_width=True)
            
            if submit_login:
                users_db = {
                    "analyst": {"password": "password123", "role": "Tier 1 SOC Analyst"},
                    "manager": {"password": "admin123", "role": "SOC Manager / Admin"}
                }
                
                if username_input in users_db and users_db[username_input]["password"] == password_input:
                    st.session_state.authenticated = True
                    st.session_state.username = username_input
                    st.session_state.role = users_db[username_input]["role"]
                    st.success("Authentication verified. Initializing secure session...")
                    st.rerun()
                else:
                    st.error("Invalid credentials. Try: `analyst` / `password123` or `manager` / `admin123`")
        st.stop()

# --- DATABASE SETUP WITH AUTO-MIGRATION & BACKUP ---
def init_db():
    conn = sqlite3.connect("soc_workbench.db", check_same_thread=False)
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS investigations (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT,
            query TEXT,
            report TEXT,
            status TEXT DEFAULT 'Open',
            severity TEXT DEFAULT 'High',
            assignee TEXT DEFAULT 'Unassigned'
        )
    """)
    
    cursor.execute("PRAGMA table_info(investigations)")
    existing_columns = [col[1] for col in cursor.fetchall()]
    
    if "status" not in existing_columns:
        cursor.execute("ALTER TABLE investigations ADD COLUMN status TEXT DEFAULT 'Open'")
    if "severity" not in existing_columns:
        cursor.execute("ALTER TABLE investigations ADD COLUMN severity TEXT DEFAULT 'High'")
    if "assignee" not in existing_columns:
        cursor.execute("ALTER TABLE investigations ADD COLUMN assignee TEXT DEFAULT 'Unassigned'")
        
    conn.commit()
    return conn

db_conn = init_db()

def auto_backup_db():
    os.makedirs("backups", exist_ok=True)
    today_str = datetime.now().strftime("%Y%m%d")
    backup_path = f"backups/soc_workbench_auto_{today_str}.db"
    if os.path.exists("soc_workbench.db") and not os.path.exists(backup_path):
        shutil.copy("soc_workbench.db", backup_path)

auto_backup_db()

if "soar_logs" not in st.session_state:
    st.session_state.soar_logs = []
if "webhook_logs" not in st.session_state:
    st.session_state.webhook_logs = []

# --- TOP NAVIGATION & HEADER BAR ---
col_logo, col_title = st.columns([0.05, 0.95])
with col_logo:
    st.markdown("<h1 style='margin: 0; font-size: 2rem;'>🛡️</h1>", unsafe_allow_html=True)
with col_title:
    st.title("ApexSOC™ | Autonomous AI Threat Intelligence & SOAR")
    st.markdown(f"⚡ **Command Center Status**: `ONLINE` &nbsp;|&nbsp; Operator: **{st.session_state.username.capitalize()}** &nbsp;|&nbsp; Clearance Level: `<span style='color: #38bdf8;'>{st.session_state.role}</span>`", unsafe_allow_html=True)

st.markdown("<div style='margin-top: -10px;'></div>", unsafe_allow_html=True)
st.markdown("---")

# --- SIDEBAR: CASE MANAGEMENT & DISASTER RECOVERY VAULT ---
st.sidebar.markdown("### 🎛️ SOC Operations Bar")
st.sidebar.markdown(f"👤 **User**: `{st.session_state.username}`")
st.sidebar.markdown(f"🛡️ **Role**: `{st.session_state.role}`")

if st.sidebar.button("🔒 Logout"):
    st.session_state.authenticated = False
    st.session_state.username = ""
    st.session_state.role = ""
    st.rerun()

st.sidebar.markdown("---")
st.sidebar.subheader("📁 Investigation Archive & Lifecycle")

cursor = db_conn.cursor()
cursor.execute("SELECT id, timestamp, query, report, status, severity, assignee FROM investigations ORDER BY id DESC")
saved_cases = cursor.fetchall()

selected_case = None
if saved_cases:
    case_titles = [f"Case #{c[0]} [{c[4]}] - {c[1][:10]}" for c in saved_cases]
    selected_index = st.sidebar.selectbox("📂 Select Active Case File", range(len(case_titles)), format_func=lambda x: case_titles[x])
    selected_case = saved_cases[selected_index]
    
    st.sidebar.markdown(f"📌 **Current Status**: `{selected_case[4]}`")
    st.sidebar.markdown(f"⚠️ **Severity**: `{selected_case[5]}`")
    st.sidebar.markdown(f"👤 **Assignee**: `{selected_case[6]}`")
    
    status_options = ["Open", "Investigating", "Contained", "Resolved", "Closed"]
    severity_options = ["Critical", "High", "Medium", "Low"]
    
    current_status_idx = status_options.index(selected_case[4]) if selected_case[4] in status_options else 0
    current_severity_idx = severity_options.index(selected_case[5]) if selected_case[5] in severity_options else 1
    
    new_status = st.sidebar.selectbox("Update Case Status", status_options, index=current_status_idx)
    new_severity = st.sidebar.selectbox("Update Severity", severity_options, index=current_severity_idx)
    
    if st.sidebar.button("💾 Save Case State"):
        cursor.execute("UPDATE investigations SET status = ?, severity = ? WHERE id = ?", (new_status, new_severity, selected_case[0]))
        db_conn.commit()
        st.sidebar.success("Case state updated!")
        st.rerun()

    if st.session_state.role == "SOC Manager / Admin":
        if st.sidebar.button("🗑️ Purge Archive", type="secondary"):
            cursor.execute("DELETE FROM investigations")
            db_conn.commit()
            st.rerun()
else:
    st.sidebar.info("✨ No active cases logged.")

# --- DISASTER RECOVERY VAULT ---
st.sidebar.markdown("---")
st.sidebar.subheader("🛡️ Disaster Recovery Vault")

if st.sidebar.button("📸 Create Instant Snapshot"):
    os.makedirs("backups", exist_ok=True)
    snapshot_name = f"backups/soc_workbench_manual_{datetime.now().strftime('%Y%m%d_%H%M%S')}.db"
    shutil.copy("soc_workbench.db", snapshot_name)
    st.sidebar.success("Snapshot saved successfully!")

if os.path.exists("backups"):
    backups_list = sorted([f for f in os.listdir("backups") if f.endswith(".db")], reverse=True)
    if backups_list:
        selected_backup = st.sidebar.selectbox("📦 Select Backup Snapshot", backups_list)
        if selected_backup:
            backup_file_path = os.path.join("backups", selected_backup)
            with open(backup_file_path, "rb") as f:
                st.sidebar.download_button(
                    label="📥 Download Snapshot",
                    data=f,
                    file_name=selected_backup,
                    mime="application/octet-stream"
                )
            
            if st.session_state.role == "SOC Manager / Admin":
                if st.sidebar.button("🔄 Restore from Snapshot", type="secondary"):
                    shutil.copy(backup_file_path, "soc_workbench.db")
                    st.sidebar.success("Platform state successfully restored!")
                    st.rerun()

uploaded_backup = st.sidebar.file_uploader("Upload Backup (.db)", type=["db"])
if uploaded_backup is not None and st.session_state.role == "SOC Manager / Admin":
    if st.sidebar.button("⚠️ Overwrite & Restore DB"):
        with open("soc_workbench.db", "wb") as f:
            f.write(uploaded_backup.read())
        st.sidebar.success("Database restored successfully from uploaded file!")
        st.rerun()

st.sidebar.markdown("---")
st.sidebar.markdown("### 🔌 Threat Feed Status")
st.sidebar.markdown("🟢 **AbuseIPDB**: Connected")
st.sidebar.markdown("🟢 **VirusTotal**: Connected")
st.sidebar.markdown("🟢 **AlienVault OTX**: Connected")
st.sidebar.markdown("🟢 **UEBA Engine**: Active")
st.sidebar.markdown("🟢 **BAS Sandbox**: Armed")

# --- GEOGRAPHIC THREAT INTELLIGENCE & TELEMETRY DASHBOARD ---
st.markdown("### 🌍 Global Threat Intelligence & Geographic Telemetry Map")
st.markdown("Real-time geo-located attack sources and telemetry nodes across global regions:")

geo_threats = pd.DataFrame([
    {"lat": 55.7558, "lon": 37.6173, "country": "Russia", "city": "Moscow", "ip": "185.220.101.5", "attacks": 420, "severity": "Critical"},
    {"lat": 39.9042, "lon": 116.4074, "country": "China", "city": "Beijing", "ip": "123.125.71.38", "attacks": 310, "severity": "High"},
    {"lat": 37.5665, "lon": 126.9780, "country": "South Korea", "city": "Seoul", "ip": "211.249.120.1", "attacks": 185, "severity": "Medium"},
    {"lat": 51.5074, "lon": -0.1278, "country": "United Kingdom", "city": "London", "ip": "82.165.188.1", "attacks": 95, "severity": "Low"},
    {"lat": 38.8951, "lon": -77.0364, "country": "United States", "city": "Washington D.C.", "ip": "198.51.100.42", "attacks": 240, "severity": "High"},
    {"lat": 28.6139, "lon": 77.2090, "country": "India", "city": "New Delhi", "ip": "103.25.14.8", "attacks": 160, "severity": "Medium"},
])

col_map, col_graph = st.columns([1.3, 1])

with col_map:
    st.markdown("#### 🗺️ Global Attack Origin Nodes & Labels")
    scatter_layer = pdk.Layer(
        "ScatterplotLayer",
        data=geo_threats,
        get_position=["lon", "lat"],
        get_radius="attacks * 1200",
        get_fill_color="[239, 68, 68, 160]",
        pickable=True,
        auto_highlight=True,
    )
    text_layer = pdk.Layer(
        "TextLayer",
        data=geo_threats,
        get_position=["lon", "lat"],
        get_text="country",
        get_size=14,
        get_color=[255, 255, 255, 220],
        get_angle=0,
        get_text_anchor=pdk.types.String("start"),
        get_alignment_baseline=pdk.types.String("center"),
        pixel_offset=[15, 0]
    )
    view_state = pdk.ViewState(latitude=20.0, longitude=0.0, zoom=1.2, pitch=20)
    r = pdk.Deck(
        layers=[scatter_layer, text_layer],
        initial_view_state=view_state,
        map_style="mapbox://styles/mapbox/dark-v10",
        tooltip={"text": "Country: {country}\nCity: {city}\nIP: {ip}\nAttacks: {attacks}\nSeverity: {severity}"}
    )
    st.pydeck_chart(r, use_container_width=True)

with col_graph:
    st.markdown("#### 📊 Threat Distribution by Country")
    fig_country = px.bar(
        geo_threats, 
        x="country", 
        y="attacks", 
        color="severity",
        color_discrete_map={"Critical": "#ef4444", "High": "#f97316", "Medium": "#eab308", "Low": "#38bdf8"},
        template="plotly_dark",
        height=380
    )
    fig_country.update_layout(
        plot_bgcolor="rgba(0,0,0,0)",
        paper_bgcolor="rgba(0,0,0,0)",
        margin=dict(l=10, r=10, t=10, b=10)
    )
    st.plotly_chart(fig_country, use_container_width=True)

st.markdown("---")

# --- ADVANCED UEBA (USER & ENTITY BEHAVIOR ANALYTICS) ---
st.markdown("### 👤 Advanced UEBA (User & Entity Behavior Analytics)")
st.markdown("Monitor behavioral baseline deviations, anomalous privileged logins, and impossible travel metrics across accounts:")

ueba_data = pd.DataFrame([
    {"User": "j.smith (SysAdmin)", "Source Workstation": "WS-012", "Login Time": "03:42 AM", "Geo Location": "Minsk, Belarus", "Risk Score": 94, "Status": "🚨 Anomalous Privileged Access"},
    {"User": "a.miller (DevOps)", "Source Workstation": "WS-088", "Login Time": "11:15 PM", "Geo Location": "Bucharest, Romania", "Risk Score": 82, "Status": "⚠️ Unusual Off-Hours Activity"},
    {"User": "m.jones (Finance)", "Source Workstation": "WS-045", "Login Time": "09:02 AM", "Geo Location": "New York, USA", "Risk Score": 12, "Status": "Normal Baseline"},
    {"User": "s.davis (SecOps)", "Source Workstation": "WS-003", "Login Time": "02:30 PM", "Geo Location": "London, UK", "Risk Score": 8, "Status": "Normal Baseline"},
    {"User": "r.wilson (HR Manager)", "Source Workstation": "WS-102", "Login Time": "04:18 AM", "Geo Location": "Lagos, Nigeria", "Risk Score": 89, "Status": "🚨 Impossible Travel Alert"}
])

col_ueba1, col_ueba2 = st.columns([2, 1])
with col_ueba1:
    st.markdown("#### 📊 Privileged Account Risk Scoreboard")
    st.dataframe(ueba_data, use_container_width=True)

with col_ueba2:
    st.markdown("#### 🔬 UEBA Insights")
    st.markdown("""
    * **Baseline Deviations**: 3 high-risk entities flagged for impossible travel and out-of-hours Kerberos ticket requests.
    * **Action**: Immediate account suspension or MFA re-challenge recommended for `j.smith`.
    """)

st.markdown("---")

# --- BREACH & ATTACK SIMULATION (BAS) SANDBOX ---
st.markdown("### 🎯 Breach & Attack Simulation (BAS) Sandbox")
st.markdown("Simulate adversary tactics against your detection rules to test defensive posture and coverage gaps:")

col_bas1, col_bas2 = st.columns([1, 1])
with col_bas1:
    selected_simulation_tactic = st.selectbox(
        "Select Attack Simulation Vector",
        [
            "T1003.001 - LSASS Memory Dumping (Mimikatz)",
            "T1021.002 - SMB/Windows Admin Shares Lateral Movement (PsExec)",
            "T1558.003 - Kerberoasting Service Principal Names",
            "T1078.004 - Cloud Account Compromise & Token Theft",
            "T1486 - Data Encrypted for Impact (Ransomware Shadow Deletion)"
        ]
    )
with col_bas2:
    st.markdown("<div style='height: 28px;'></div>", unsafe_allow_html=True)
    run_sim_btn = st.button("Execute Attack Simulation & Audit Rules")

if run_sim_btn:
    with st.spinner("Executing simulation telemetry and evaluating EDR/SIEM detection rule coverage..."):
        bas_prompt = [
            {
                "role": "system",
                "content": (
                    "You are a Lead Red Teamer and Detection Validation Engineer. "
                    "Analyze the selected breach simulation vector and provide:\n"
                    "1. **Simulation Attack Flow & Execution Steps**\n"
                    "2. **Expected Telemetry Artifacts Generated** (Sysmon Event IDs, Windows Security Logs)\n"
                    "3. **Detection Rule Coverage Evaluation** (Are standard SIEM queries or Sigma rules catching this?)\n"
                    "4. **Hardening & Mitigation Recommendations**"
                )
            },
            {"role": "user", "content": f"Selected Tactic: {selected_simulation_tactic}"}
        ]
        bas_res = client.chat.completions.create(
            model="gpt-4o-mini",
            messages=bas_prompt,
            temperature=0.3
        )
        st.markdown("### 🧪 BAS Simulation & Detection Audit Report")
        st.markdown(bas_res.choices[0].message.content)

st.markdown("---")

# --- PROACTIVE CTI & THREAT HUNTING HYPOTHESIS STUDIO ---
st.markdown("### 🎯 Proactive CTI & Campaign Threat Hunting Studio")
col_hunt1, col_hunt2 = st.columns([1, 1])
with col_hunt1:
    selected_threat_group = st.selectbox(
        "Select Target Adversary Group / Campaign",
        [
            "APT29 (Cozy Bear) - Spearphishing & Cloud Token Theft",
            "APT28 (Fancy Bear) - Credential Harvesting & Router Exploitation",
            "Lazarus Group - Supply Chain & Cryptomining Persistence",
            "FIN7 - PowerShell C2 & Living-off-the-Land Binaries",
            "LockBit Ransomware - Active Directory Enumeration & Volume Shadow Purging",
            "Custom CTI Bulletin / Threat Briefing"
        ]
    )
with col_hunt2:
    st.markdown("<div style='height: 28px;'></div>", unsafe_allow_html=True)
    run_threat_hunt = st.button("Generate Proactive Hunting Package")

custom_cti_input = st.text_area(
    "Threat Intelligence Bulletin / Campaign Details (Optional Custom Input)", 
    placeholder="Paste CTI report, TTP descriptions, or indicator notes here...",
    height=85
)

if run_threat_hunt:
    with st.spinner("Synthesizing CTI feed and constructing threat hunting hypothesis package..."):
        hunt_prompt = [
            {
                "role": "system",
                "content": (
                    "You are an elite Lead Threat Hunter and Cyber Threat Intelligence (CTI) Analyst. "
                    "Generate a comprehensive Proactive Threat Hunting Package containing:\n"
                    "1. **Threat Campaign & TTP Overview**\n"
                    "2. **Proactive Threat Hunting Hypothesis**\n"
                    "3. **Required Telemetry & Data Sources**\n"
                    "4. **Multi-Platform Hunting Queries** (Sentinel KQL, Splunk SPL, Sigma Rule)\n"
                    "5. **Cyber Kill Chain Progression**"
                )
            },
            {"role": "user", "content": f"Selected Group: {selected_threat_group}\nCustom Notes: {custom_cti_input}"}
        ]
        hunt_res = client.chat.completions.create(
            model="gpt-4o-mini",
            messages=hunt_prompt,
            temperature=0.3
        )
        st.markdown("### 🔬 Proactive Threat Hunting Package Output")
        st.markdown(hunt_res.choices[0].message.content)

st.markdown("---")

# --- AI-DRIVEN MALWARE DEOBFUSCATION & SCRIPT ANALYSIS STUDIO ---
st.markdown("### 🧬 AI-Driven Malware Deobfuscation & Script Analysis Studio")
col_mal1, col_mal2 = st.columns([3, 1])
with col_mal1:
    obfuscated_script_input = st.text_area(
        "Obfuscated Script / Payload Input", 
        placeholder="Paste obfuscated PowerShell (e.g., -enc, iex), base64 encoded strings, or suspicious macro code here...",
        height=110
    )
with col_mal2:
    st.markdown("<div style='height: 28px;'></div>", unsafe_allow_html=True)
    run_deobfuscate = st.button("Deobfuscate & Analyze Script")

if run_deobfuscate and obfuscated_script_input:
    with st.spinner("Unwrapping encoding layers, analyzing behavioral intent, and extracting embedded IOCs..."):
        malware_prompt = [
            {
                "role": "system",
                "content": (
                    "You are an expert Reverse Engineer and Malware Analyst. "
                    "Analyze the provided obfuscated script. Provide:\n"
                    "1. **Executive Verdict & Threat Classification**\n"
                    "2. **Deobfuscated & Cleaned Code**\n"
                    "3. **Behavioral Intent & Capability Analysis**\n"
                    "4. **Extracted IOCs**\n"
                    "5. **MITRE ATT&CK Technique Mapping**"
                )
            },
            {"role": "user", "content": obfuscated_script_input}
        ]
        malware_res = client.chat.completions.create(
            model="gpt-4o-mini",
            messages=malware_prompt,
            temperature=0.1
        )
        st.markdown("### 🔍 Malware Analysis & Deobfuscation Report")
        st.markdown(malware_res.choices[0].message.content)

st.markdown("---")

# --- NATURAL LANGUAGE TO SQL QUERY ENGINE ---
st.markdown("### 💬 Natural Language Intelligence & Case Search (Text-to-SQL)")
col_nl1, col_nl2 = st.columns([4, 1])
with col_nl1:
    nl_prompt = st.text_input("Natural Language Search", placeholder="e.g., Show me all critical severity investigations or cases mentioning IP 185.220.101.5")
with col_nl2:
    st.markdown("<div style='height: 28px;'></div>", unsafe_allow_html=True)
    run_nl_query = st.button("Run NL Query")

if run_nl_query and nl_prompt:
    with st.spinner("Translating natural language into secure SQLite query..."):
        sql_prompt = [
            {
                "role": "system",
                "content": (
                    "You are an expert SQLite database analyst. Given the SQLite table `investigations` with columns: "
                    "`id` (INTEGER), `timestamp` (TEXT), `query` (TEXT), `report` (TEXT), `status` (TEXT), `severity` (TEXT), `assignee` (TEXT). "
                    "Write a valid, safe, read-only SQL SELECT query that answers the user's request. "
                    "Return ONLY the executable SQL query inside a markdown code block."
                )
            },
            {"role": "user", "content": nl_prompt}
        ]
        sql_response = client.chat.completions.create(
            model="gpt-4o-mini",
            messages=sql_prompt,
            temperature=0
        )
        raw_sql_text = sql_response.choices[0].message.content
        sql_match = re.search(r"```(?:sql)?\n(.*?)\n```", raw_sql_text, re.DOTALL)
        clean_sql = sql_match.group(1).strip() if sql_match else raw_sql_text.strip()

    st.markdown(f"**Generated SQL Query:**")
    st.code(clean_sql, language="sql")

    try:
        df_result = pd.read_sql_query(clean_sql, db_conn)
        st.markdown(f"**Query Results ({len(df_result)} records found):**")
        st.dataframe(df_result, use_container_width=True)
    except Exception as e:
        st.error(f"Error executing generated SQL query: {e}")

st.markdown("---")

# --- AI-DRIVEN LOG SCHEMA NORMALIZATION ---
st.markdown("### 🔄 AI-Driven Log Schema Normalization (OCSF / ECS Parser)")
col_norm1, col_norm2 = st.columns([3, 1])
with col_norm1:
    raw_log_snippet = st.text_area("Unformatted Raw Log / Syslog Snippet", placeholder="Paste custom legacy syslog or vendor log text here...", height=90)
with col_norm2:
    st.markdown("<div style='height: 28px;'></div>", unsafe_allow_html=True)
    normalize_btn = st.button("Normalize to OCSF Schema")

if normalize_btn and raw_log_snippet:
    with st.spinner("Parsing and mapping fields to Open Cybersecurity Schema Framework (OCSF)..."):
        norm_prompt = [
            {
                "role": "system",
                "content": (
                    "You are an automated cybersecurity log normalization and parsing engine. "
                    "Parse the provided raw log snippet and map its fields into a standardized JSON format adhering to OCSF. "
                    "Include keys: `timestamp`, `actor_ip`, `target_ip`, `activity_name`, `severity`, and `raw_parsed_data`. "
                    "Output ONLY valid JSON."
                )
            },
            {"role": "user", "content": raw_log_snippet}
        ]
        norm_res = client.chat.completions.create(
            model="gpt-4o-mini",
            messages=norm_prompt,
            temperature=0,
            response_format={"type": "json_object"}
        )
        st.markdown("**Normalized OCSF JSON Output:**")
        st.code(norm_res.choices[0].message.content, language="json")

st.markdown("---")
st.markdown("### 🎯 Incident Input & Artifact Submission")

uploaded_file = st.file_uploader("📁 Upload Log File for AI Analysis (TXT, LOG, CSV, JSON)", type=["txt", "log", "csv", "json"])

file_content = ""
if uploaded_file is not None:
    try:
        if uploaded_file.name.endswith('.csv'):
            df_upload = pd.read_csv(uploaded_file)
            file_content = df_upload.to_string()
        else:
            file_content = uploaded_file.read().decode("utf-8", errors="ignore")
        st.success(f"Successfully loaded file: `{uploaded_file.name}` ({len(file_content)} characters)")
    except Exception as e:
        st.error(f"Error parsing uploaded file: {e}")

default_query = selected_case[2] if selected_case else """[ALERT] Potential C2 beacon detected on workstation WS-089. 
Raw log snippet: Connection established from internal IP 10.0.4.5 to external suspicious IP 185.220.101.5 over port 443. 
Associated dropped file hash on disk: 44d88612fea8a8f36de82e1278abb02f. Please investigate and map to MITRE ATT&CK."""

if file_content:
    default_query = f"[UPLOADED LOG FILE: {uploaded_file.name}]\n\n{file_content[:10000]}"

user_query = st.text_area("Investigation Telemetry, Logs, or Incident Artifacts:", default_query, height=150)

# --- MACHINE LEARNING MODULE: ISOLATION FOREST ANOMALY SCORING ---
st.markdown("### 🤖 ML Behavioral Outlier Detection Engine")
np.random.seed(42)
normal_traffic = np.random.normal(loc=500, scale=100, size=(95, 2))
outlier_traffic = np.array([[4500, 1200], [3800, 950], [5200, 1500]])
synthetic_data = np.vstack([normal_traffic, outlier_traffic])

df_logs = pd.DataFrame(synthetic_data, columns=["Bytes Transferred", "Session Duration (s)"])
df_logs["Source IP"] = [f"10.0.4.{i%254}" for i in range(len(df_logs))]
df_logs.loc[95:, "Source IP"] = "185.220.101.5"

iso_model = IsolationForest(contamination=0.03, random_state=42)
df_logs["Anomaly Score"] = iso_model.fit_predict(df_logs[["Bytes Transferred", "Session Duration (s)"]])
df_logs["ML Verdict"] = df_logs["Anomaly Score"].apply(lambda x: "🚨 High-Risk Outlier" if x == -1 else "Normal")

total_flows = len(df_logs)
outlier_count = int((df_logs["ML Verdict"] == "🚨 High-Risk Outlier").sum())

col_m1, col_m2, col_m3 = st.columns(3)
with col_m1:
    st.metric("Total Analyzed Flows", total_flows, delta="Real-time buffer")
with col_m2:
    st.metric("Outliers Flagged", outlier_count, delta="Anomaly threshold 3%", delta_color="inverse")
with col_m3:
    st.metric("Model Status", "Active / Online", delta="Isolation Forest")

st.markdown("#### 🔬 Flagged Behavioral Anomalies")
st.dataframe(df_logs[df_logs["ML Verdict"] == "🚨 High-Risk Outlier"], use_container_width=True)

# --- SMART REGEX IOC EXTRACTOR ---
def extract_iocs(text: str):
    ips = list(set(re.findall(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b', text)))
    hashes = list(set(re.findall(r'\b[a-fA-F0-9]{32}\b|\b[a-fA-F0-9]{40}\b|\b[a-fA-F0-9]{64}\b', text)))
    return ips, hashes

def truncate_json(data_str: str, max_chars: int = 4000) -> str:
    if len(data_str) > max_chars:
        return data_str[:max_chars] + "\n[TRUNCATED DUE TO SIZE]"
    return data_str

# --- SECURITY API TOOL DEFINITIONS ---
def check_abuse_ipdb(ip_address: str) -> str:
    api_key = os.getenv("ABUSEIPDB_API_KEY")
    if not api_key:
        return json.dumps({
            "ip": ip_address,
            "status": "Mock Mode (No API Key)",
            "abuseConfidenceScore": 88 if ip_address == "185.220.101.5" else 5,
            "countryCode": "RU" if ip_address == "185.220.101.5" else "US",
            "usageType": "Tor Exit Node" if ip_address == "185.220.101.5" else "Data Center",
            "totalReports": 342 if ip_address == "185.220.101.5" else 0
        })
    try:
        url = "https://api.abuseipdb.com/api/v2/check"
        headers = {"Accept": "application/json", "Key": api_key}
        params = {"ipAddress": ip_address, "maxAgeInDays": "90"}
        response = httpx.get(url, headers=headers, params=params, timeout=5.0)
        return truncate_json(response.text)
    except Exception as e:
        return json.dumps({"error": f"AbuseIPDB Lookup Failed: {str(e)}"})

def check_virustotal(hash_or_ip: str) -> str:
    api_key = os.getenv("VIRUSTOTAL_API_KEY")
    if not api_key:
        return json.dumps({
            "resource": hash_or_ip,
            "status": "Mock Mode (No API Key)",
            "positives": 48 if len(hash_or_ip) == 32 or hash_or_ip == "185.220.101.5" else 0,
            "total": 72,
            "scan_date": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "threat_classification": "Trojan.Generic.CobaltStrike" if len(hash_or_ip) == 32 else "Clean"
        })
    try:
        url = f"https://www.virustotal.com/api/v3/search?query={hash_or_ip}"
        headers = {"x-apikey": api_key}
        response = httpx.get(url, headers=headers, timeout=5.0)
        return truncate_json(response.text)
    except Exception as e:
        return json.dumps({"error": f"VirusTotal Lookup Failed: {str(e)}"})

# --- EXECUTE INVESTIGATION & THREAT ENRICHMENT ---
st.markdown("### ⚡ AI Automated Threat Investigation")

col_inv1, col_inv2 = st.columns([1, 1])
with col_inv1:
    run_investigation_btn = st.button("🚀 Run Deep Threat Investigation & CTI Enrichment")

if run_investigation_btn and user_query:
    extracted_ips, extracted_hashes = extract_iocs(user_query)
    
    st.markdown("#### 🔎 Discovered IOCs & Real-Time Enrichment")
    
    enrichment_results = {}
    
    with st.spinner("Queries sent to CTI feeds (AbuseIPDB & VirusTotal)..."):
        for ip in extracted_ips:
            res_ip = check_abuse_ipdb(ip)
            enrichment_results[f"IP_{ip}"] = json.loads(res_ip)
            st.write(f"🌐 **IP Enrichment [{ip}]**: Score `{enrichment_results[f'IP_{ip}'].get('abuseConfidenceScore', 'N/A')}%`")
            
        for h in extracted_hashes:
            res_vt = check_virustotal(h)
            enrichment_results[f"HASH_{h}"] = json.loads(res_vt)
            st.write(f"🦠 **Hash Enrichment [{h}]**: Detection `{enrichment_results[f'HASH_{h}'].get('positives', 0)}/{enrichment_results[f'HASH_{h}'].get('total', 0)}`")

    with st.spinner("Synthesizing telemetry and generating executive threat report..."):
        soc_system_prompt = (
            "You are ApexSOC, an autonomous AI Security Operations Center Lead Analyst. "
            "Perform a rigorous threat investigation on the submitted telemetry and enriched CTI data. "
            "Generate a formal SOC Incident Response Report containing:\n"
            "1. **Executive Summary & Verdict** (Critical / High / Medium / Low)\n"
            "2. **Extracted Key Indicators of Compromise (IOCs)**\n"
            "3. **Threat Intelligence Synthesis** (AbuseIPDB & VirusTotal Findings)\n"
            "4. **MITRE ATT&CK Matrix Mapping** (Tactics, Techniques, and IDs)\n"
            "5. **Root Cause & Technical Analysis**\n"
            "6. **Recommended Immediate SOAR Playbooks & Containment Actions**"
        )
        
        user_prompt_content = f"Telemetry Log Input:\n{user_query}\n\nEnrichment CTI Output:\n{json.dumps(enrichment_results, indent=2)}"
        
        analysis_response = client.chat.completions.create(
            model="gpt-4o-mini",
            messages=[
                {"role": "system", "content": soc_system_prompt},
                {"role": "user", "content": user_prompt_content}
            ],
            temperature=0.2
        )
        
        final_report = analysis_response.choices[0].message.content

        # Save investigation into DB
        cursor = db_conn.cursor()
        now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        cursor.execute(
            "INSERT INTO investigations (timestamp, query, report, status, severity, assignee) VALUES (?, ?, ?, 'Open', 'High', ?)",
            (now_str, user_query, final_report, st.session_state.username)
        )
        db_conn.commit()
        
        st.markdown("### 📋 Executive Investigation Report")
        st.markdown(final_report)

# --- SOAR (SECURITY ORCHESTRATION, AUTOMATION & RESPONSE) ACTION HUB ---
st.markdown("---")
st.markdown("### 🛠️ SOAR Autonomous Action & Playbook Hub")
st.markdown("Trigger automated containment playbooks and webhook integrations to neutralize threats in real time:")

col_play1, col_play2, col_play3 = st.columns(3)

with col_play1:
    if st.button("🚫 Firewall Block IP (Palo Alto / Fortinet)"):
        timestamp = datetime.now().strftime("%H:%M:%S")
        action_log = f"[{timestamp}] [FIREWALL] Automated block rule applied for malicious IP 185.220.101.5 on perimeter firewall."
        st.session_state.soar_logs.append(action_log)
        st.success("Playbook Executed: IP Blocked")

with col_play2:
    if st.button("💻 EDR Workstation Isolation (CrowdStrike / Defender)"):
        timestamp = datetime.now().strftime("%H:%M:%S")
        action_log = f"[{timestamp}] [EDR] Network isolation command dispatched to Workstation WS-089."
        st.session_state.soar_logs.append(action_log)
        st.success("Playbook Executed: Workstation Isolated")

with col_play3:
    if st.button("🔑 Revoke User OAuth / Reset Session (Entra ID)"):
        timestamp = datetime.now().strftime("%H:%M:%S")
        action_log = f"[{timestamp}] [IDENTITY] Active refresh tokens revoked & password reset enforced for user j.smith."
        st.session_state.soar_logs.append(action_log)
        st.success("Playbook Executed: Account Secured")

# --- WEBHOOK / SLACK / TEAMS DISPATCH ENGINE ---
st.markdown("#### 📡 Incident Notification & Webhook Dispatch")
col_web1, col_web2 = st.columns([3, 1])
with col_web1:
    webhook_url = st.text_input("Webhook Destination Endpoint (Slack / Microsoft Teams / Webhook.site)", placeholder="https://hooks.slack.com/services/...")
with col_web2:
    st.markdown("<div style='height: 28px;'></div>", unsafe_allow_html=True)
    send_webhook_btn = st.button("Dispatched SOAR Alert Webhook")

if send_webhook_btn and webhook_url:
    payload = {
        "text": "🚨 **ApexSOC Critical Incident Alert** 🚨",
        "attachments": [
            {
                "color": "#ef4444",
                "fields": [
                    {"title": "Operator", "value": st.session_state.username, "short": True},
                    {"title": "Severity", "value": "CRITICAL", "short": True},
                    {"title": "Summary", "value": "Potential C2 Beaconing to Tor Exit Node detected on WS-089.", "short": False}
                ]
            }
        ]
    }
    try:
        response = httpx.post(webhook_url, json=payload, timeout=5.0)
        timestamp = datetime.now().strftime("%H:%M:%S")
        st.session_state.webhook_logs.append(f"[{timestamp}] Webhook dispatched to {webhook_url} - Status Code: {response.status_code}")
        st.success(f"Webhook dispatched successfully (Status {response.status_code})!")
    except Exception as e:
        st.error(f"Failed to dispatch webhook: {e}")

# --- REAL-TIME SOAR AUDIT LOG STREAM ---
if st.session_state.soar_logs or st.session_state.webhook_logs:
    st.markdown("#### 📜 Operational SOAR Audit Trail")
    for log in st.session_state.soar_logs + st.session_state.webhook_logs:
        st.code(log, language="bash")
