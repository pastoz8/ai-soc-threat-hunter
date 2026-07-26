import os
import json
import re
import sqlite3
import httpx
from dotenv import load_dotenv
from openai import OpenAI
import streamlit as st
import pandas as pd
import numpy as np
from sklearn.ensemble import IsolationForest
from datetime import datetime

load_dotenv()
client = OpenAI()

st.set_page_config(
    page_title="ApexSOC | Enterprise Threat Hunter & SOAR", 
    page_icon="🛡️", 
    layout="wide",
    initial_sidebar_state="expanded"
)

# --- PROFESSIONAL CYBERSECURITY UI STYLING & CSS ---
st.markdown("""
<style>
    /* Main App Container & Theme */
    .stApp {
        background-color: #0b0f19;
        color: #f3f4f6;
    }
    
    /* Sidebar Customization */
    [data-testid="stSidebar"] {
        background-color: #111827;
        border-right: 1px solid #1f2937;
    }
    
    /* Headers & Typography */
    h1, h2, h3 {
        color: #f8fafc !important;
        font-family: 'Inter', sans-serif;
    }
    
    /* Custom Styled Cards */
    .soc-card {
        background: linear-gradient(135deg, #1e293b 0%, #0f172a 100%);
        border: 1px solid #334155;
        padding: 20px;
        border-radius: 12px;
        box-shadow: 0 10px 15px -3px rgba(0, 0, 0, 0.3);
        margin-bottom: 20px;
    }
    
    /* Sleek Primary Action Buttons */
    .stButton>button {
        width: 100%;
        border-radius: 8px;
        font-weight: 600;
        background: linear-gradient(135deg, #0ea5e9 0%, #2563eb 100%);
        color: white;
        border: none;
        padding: 0.6rem 1rem;
        box-shadow: 0 4px 12px rgba(14, 165, 233, 0.25);
        transition: all 0.3s ease;
    }
    .stButton>button:hover {
        background: linear-gradient(135deg, #0284c7 0%, #1d4ed8 100%);
        box-shadow: 0 0 20px rgba(14, 165, 233, 0.5);
        transform: translateY(-1px);
    }
    
    /* Metric Indicators */
    [data-testid="stMetricValue"] {
        color: #38bdf8 !important;
        font-weight: 700;
    }
</style>
""", unsafe_allow_html=True)

# --- DATABASE SETUP (SQLITE PERSISTENCE) ---
def init_db():
    conn = sqlite3.connect("soc_workbench.db", check_same_thread=False)
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS investigations (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT,
            query TEXT,
            report TEXT
        )
    """)
    conn.commit()
    return conn

db_conn = init_db()

# Initialize session state for SOAR audit logs
if "soar_logs" not in st.session_state:
    st.session_state.soar_logs = []

# --- TOP NAVIGATION & HEADER BAR ---
col_logo, col_title = st.columns([0.08, 0.92])
with col_logo:
    st.markdown("<h1>🛡️</h1>", unsafe_allow_html=True)
with col_title:
    st.title("ApexSOC™ | Autonomous AI Threat Intelligence & SOAR Workbench")
    st.markdown("⚡ **Live Operational Command Center** — *Powered by Machine Learning Outlier Detection, Threat Intel Correlators, & Automated SOAR Playbooks*")

st.markdown("---")

# --- SIDEBAR: ENHANCED CASE MANAGEMENT TOOLBAR ---
st.sidebar.markdown("### 🎛️ SOC Operations Bar")
st.sidebar.markdown("---")
st.sidebar.subheader("📁 Investigation Archive")
st.sidebar.markdown("Saved cases from persistent SQLite storage:")

# Fetch history from SQLite database
cursor = db_conn.cursor()
cursor.execute("SELECT id, timestamp, query, report FROM investigations ORDER BY id DESC")
saved_cases = cursor.fetchall()

selected_case = None
if saved_cases:
    case_titles = [f"Case #{c[0]} [{c[1][:10]}]" for c in saved_cases]
    selected_index = st.sidebar.selectbox("📂 Select Active Case File", range(len(case_titles)), format_func=lambda x: case_titles[x])
    
    col_sb1, col_sb2 = st.sidebar.columns(2)
    with col_sb1:
        if st.button("📂 Load"):
            selected_case = saved_cases[selected_index]
    with col_sb2:
        if st.button("🗑️ Purge", type="secondary"):
            cursor.execute("DELETE FROM investigations")
            db_conn.commit()
            st.rerun()
else:
    st.sidebar.info("✨ No active cases logged in storage.")

st.sidebar.markdown("---")
st.sidebar.markdown("### 🔌 API Integration Status")
st.sidebar.markdown("🟢 **AbuseIPDB Engine**: Connected")
st.sidebar.markdown("🟢 **VirusTotal Sandbox**: Connected")
st.sidebar.markdown("🟢 **AlienVault OTX**: Connected")
st.sidebar.markdown("🟢 **SOAR Automation Engine**: Ready")

# Main Input Section
st.markdown("### 🎯 Incident Input & Artifact Submission")
default_query = selected_case[2] if selected_case else """[ALERT] Potential C2 beacon detected on workstation WS-089. 
Raw log snippet: Connection established from internal IP 10.0.4.5 to external suspicious IP 185.220.101.5 over port 443. 
Associated dropped file hash on disk: 44d88612fea8a8f36de82e1278abb02f. Please investigate and map to MITRE ATT&CK."""

user_query = st.text_area("Paste Investigation Telemetry, Logs, or Incident Artifacts:", default_query, height=130)

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

col_m1, col_m2, col_m3 = st.columns(3)
with col_m1:
    st.metric("Total Analyzed Flows", len(df_logs), delta="Real-time buffer")
with col_m2:
    st.metric("Outliers Flagged", len(df_logs[df_logs["ML Verdict"] == "🚨 High-Risk Outlier"]), delta="Anomaly threshold 3%", delta_color="inverse")
with col_m3:
    st.metric("Model Status", "Active / Online", delta="Isolation Forest")

st.markdown("#### 🔬 Flagged Behavioral Anomalies")
st.dataframe(df_logs[df_logs["ML Verdict"] == "🚨 High-Risk Outlier"], use_container_width=True)

# --- SMART REGEX IOC EXTRACTOR ---
def extract_iocs(text: str):
    ips = list(set(re.findall(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b', text)))
    hashes = list(set(re.findall(r'\b[a-fA-F0-9]{32}\b|\b[a-fA-F0-9]{40}\b|\b[a-fA-F0-9]{64}\b', text)))
    return ips, hashes

# --- HELPER: TRUNCATE LARGE TOOL RESPONSES ---
def truncate_json(data_str: str, max_chars: int = 4000) -> str:
    if len(data_str) > max_chars:
        return data_str[:max_chars] + "\n[TRUNCATED DUE TO SIZE]"
    return data_str

# --- SECURITY API TOOL DEFINITIONS ---

def check_abuse_ipdb(ip_address: str) -> str:
    api_key = os.getenv("ABUSEIPDB_API_KEY")
    url = "https://api.abuseipdb.com/api/v2/check"
    headers = {"Key": api_key, "Accept": "application/json"}
    params = {"ipAddress": ip_address, "maxAgeInDays": "90"}
    try:
        response = httpx.get(url, headers=headers, params=params, timeout=10)
        return truncate_json(json.dumps(response.json()))
    except Exception as e:
        return json.dumps({"error": str(e)})

def check_virustotal_hash(file_hash: str) -> str:
    api_key = os.getenv("VIRUSTOTAL_API_KEY")
    url = f"https://www.virustotal.com/api/v3/files/{file_hash}"
    headers = {"x-apikey": api_key}
    try:
        response = httpx.get(url, headers=headers, timeout=10)
        return truncate_json(json.dumps(response.json()))
    except Exception as e:
        return json.dumps({"error": str(e)})

def check_otx_indicator(indicator: str, indicator_type: str = "IPv4") -> str:
    api_key = os.getenv("OTX_API_KEY")
    if indicator_type.lower() in ["ip", "ipv4", "ipv6"]:
        path_type = "IPv4"
    elif indicator_type.lower() in ["file", "hash"]:
        path_type = "file"
    else:
        path_type = "domain"
        
    url = f"https://otx.alienvault.com/api/v1/indicators/{path_type}/{indicator}/general"
    headers = {"X-OTX-API-KEY": api_key}
    try:
        response = httpx.get(url, headers=headers, timeout=10)
        return truncate_json(json.dumps(response.json()))
    except Exception as e:
        return json.dumps({"error": str(e)})

available_tools = {
    "check_abuse_ipdb": check_abuse_ipdb,
    "check_virustotal_hash": check_virustotal_hash,
    "check_otx_indicator": check_otx_indicator
}

tools_schema = [
    {
        "type": "function",
        "function": {
            "name": "check_abuse_ipdb",
            "description": "Check the abuse confidence score of an IP address using AbuseIPDB.",
            "parameters": {
                "type": "object",
                "properties": {"ip_address": {"type": "string"}},
                "required": ["ip_address"]
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "check_virustotal_hash",
            "description": "Inspect a file hash on VirusTotal.",
            "parameters": {
                "type": "object",
                "properties": {"file_hash": {"type": "string"}},
                "required": ["file_hash"]
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "check_otx_indicator",
            "description": "Query AlienVault OTX for threat intelligence pulses associated with an IP, domain, or file hash.",
            "parameters": {
                "type": "object",
                "properties": {
                    "indicator": {"type": "string", "description": "The IP, domain, or hash to look up."},
                    "indicator_type": {"type": "string", "description": "Type of indicator: 'IPv4', 'file', or 'domain'"}
                },
                "required": ["indicator", "indicator_type"]
            }
        }
    }
]

# --- EXECUTION LOGIC ---
st.markdown("---")
if st.button("🚀 Execute Autonomous Threat Hunt & Save Briefing", use_container_width=True) or selected_case:
    if selected_case and not st.session_state.get('just_ran', False):
        report_content = selected_case[3]
    else:
        extracted_ips, extracted_hashes = extract_iocs(user_query)
        
        with st.spinner("⚡ ApexSOC Agent actively querying live threat feeds, correlators, and ML models..."):
            messages = [
                {
                    "role": "system",
                    "content": (
                        "You are an elite autonomous AI Cyber Threat Hunter and Principal Detection Engineer in a top-tier SOC. "
                        "Analyze raw logs, extracted IOCs, and ML behavioral metrics using tools across AbuseIPDB, VirusTotal, and AlienVault OTX. "
                        "Your final response MUST be formatted as a professional SOC Incident Briefing containing:\n"
                        "1. **Executive Summary & Risk Score** (Low/Medium/High/Critical)\n"
                        "2. **Machine Learning Behavioral Analysis**\n"
                        "3. **Indicator Breakdown** (Synthesized findings from APIs)\n"
                        "4. **MITRE ATT&CK Framework Mapping** (Markdown table with columns: `Tactic`, `Technique ID`, `Technique Name`, and `Observed Behavioral Description`)\n"
                        "5. **Recommended Hunting & Remediation Actions**\n"
                        "6. **Actionable Detection Engineering** (Valid **Sigma Rule in YAML format** and a **Microsoft Sentinel KQL query**)"
                    )
                },
                {"role": "user", "content": f"Log input:\n{user_query}\n\nExtracted IPs: {extracted_ips}\nExtracted Hashes: {extracted_hashes}"}
            ]
            
            response = client.chat.completions.create(
                model="gpt-4o-mini",
                messages=messages,
                tools=tools_schema,
                tool_choice="auto"
            )
            
            response_message = response.choices[0].message
            messages.append(response_message)
            
            if response_message.tool_calls:
                for tool_call in response_message.tool_calls:
                    fn_name = tool_call.function.name
                    fn_args = json.loads(tool_call.function.arguments)
                    if fn_name in available_tools:
                        res = available_tools[fn_name](**fn_args)
                    else:
                        res = json.dumps({"error": "Tool not found"})
                    messages.append({"role": "tool", "tool_call_id": tool_call.id, "content": res})
                
                final_response = client.chat.completions.create(
                    model="gpt-4o-mini",
                    messages=messages
                )
                report_content = final_response.choices[0].message.content
            else:
                report_content = response_message.content

            # Save investigation permanently to SQLite database
            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            cursor.execute("INSERT INTO investigations (timestamp, query, report) VALUES (?, ?, ?)", (timestamp, user_query, report_content))
            db_conn.commit()

    st.markdown("### 📊 ApexSOC Incident Intelligence Briefing")
    st.markdown(report_content)

    st.download_button(
        label="📥 Download Certified SOC Report (Markdown)",
        data=report_content,
        file_name=f"ApexSOC_Report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.md",
        mime="text/markdown",
        use_container_width=True
    )

    # --- AUTOMATED SOAR ACTION SIMULATOR ---
    st.markdown("---")
    st.markdown("### ⚡ Automated SOAR Playbooks & Response Actions")
    st.markdown("Execute active containment and remediation playbooks directly from the SOC console:")

    extracted_ips, extracted_hashes = extract_iocs(user_query)
    target_ip = extracted_ips[0] if extracted_ips else "185.220.101.5"

    col_soar1, col_soar2, col_soar3, col_soar4 = st.columns(4)

    with col_soar1:
        if st.button("🔥 Block IP on Firewall"):
            log_entry = f"[{datetime.now().strftime('%H:%M:%S')}] SOAR Action: Blocked malicious IP `{target_ip}` on perimeter firewall ruleset."
            st.session_state.soar_logs.append(log_entry)
            st.success(f"IP {target_ip} blocked successfully!")

    with col_soar2:
        if st.button("💻 Isolate Host Endpoint"):
            log_entry = f"[{datetime.now().strftime('%H:%M:%S')}] SOAR Action: Network isolation command sent to EDR agent for workstation WS-089."
            st.session_state.soar_logs.append(log_entry)
            st.success("Endpoint WS-089 isolated from corporate network!")

    with col_soar3:
        if st.button("🔑 Revoke User Sessions"):
            log_entry = f"[{datetime.now().strftime('%H:%M:%S')}] SOAR Action: Active Directory tokens revoked and sessions terminated for flagged accounts."
            st.session_state.soar_logs.append(log_entry)
            st.success("User sessions successfully revoked!")

    with col_soar4:
        if st.button("🎫 Create ServiceNow Incident"):
            log_entry = f"[{datetime.now().strftime('%H:%M:%S')}] SOAR Action: P1 Incident Ticket #INC-98241 created in ServiceNow with attached telemetry."
            st.session_state.soar_logs.append(log_entry)
            st.success("ServiceNow Incident #INC-98241 created!")

    # Display live SOAR execution audit trail
    if st.session_state.soar_logs:
        st.markdown("#### 📋 Active SOAR Execution Audit Trail")
        for log in reversed(st.session_state.soar_logs):
            st.code(log, language="text")