import os
import json
import re
import httpx
from dotenv import load_dotenv
from openai import OpenAI
import streamlit as st
from datetime import datetime

load_dotenv()
client = OpenAI()

st.set_page_config(page_title="AI SOC Threat Hunter Workbench", page_icon="🛡️", layout="wide")

# Initialize Session State for Case History
if "history" not in st.session_state:
    st.session_state.history = []

st.title("🛡️ AI-Assisted SOC Threat Hunter Workbench")
st.markdown("Autonomous threat intelligence, **MITRE ATT&CK mapping**, **Automated Detection Engineering**, and **Smart IOC Extraction**.")

# --- SIDEBAR: CASE HISTORY ARCHIVE ---
st.sidebar.title("📁 Investigation Cases")
st.sidebar.markdown("Active session history of threat hunts:")

selected_case = None
if st.session_state.history:
    case_titles = [f"Case #{i+1}: {c['query'][:30]}..." for i, c in enumerate(st.session_state.history)]
    selected_index = st.sidebar.selectbox("Select Past Investigation", range(len(case_titles)), format_func=lambda x: case_titles[x])
    if st.sidebar.button("Load Selected Case"):
        selected_case = st.session_state.history[selected_index]
else:
    st.sidebar.info("No investigations logged in this session yet.")

if st.sidebar.button("Clear History"):
    st.session_state.history = []
    st.rerun()

# Main Input Form (Simulating a messy SIEM log or incident ticket)
default_query = selected_case["query"] if selected_case else """[ALERT] Potential C2 beacon detected on workstation WS-089. 
Raw log snippet: Connection established from internal IP 10.0.4.5 to external suspicious IP 185.220.101.5 over port 443. 
Associated dropped file hash on disk: 44d88612fea8a8f36de82e1278abb02f. Please investigate and map to MITRE ATT&CK."""

user_query = st.text_area("Paste Messy SIEM Log, Email Header, or Incident Ticket:", default_query, height=130)

# --- SMART REGEX IOC EXTRACTOR ---
def extract_iocs(text: str):
    """Automatically parses IPs, hashes (MD5/SHA256), and domains from unstructured log text."""
    # IPv4 regex pattern
    ips = list(set(re.findall(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b', text)))
    # Hash regex pattern (MD5, SHA1, SHA256)
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

if st.button("Extract IOCs & Run Automated Threat Hunt") or selected_case:
    if selected_case and not st.session_state.get('just_ran', False):
        report_content = selected_case["report"]
    else:
        # Step A: Automatically extract IOCs from raw text
        extracted_ips, extracted_hashes = extract_iocs(user_query)
        
        # Display parsed indicators dynamically in the UI
        col1, col2 = st.columns(2)
        with col1:
            st.info(f"**Parsed IPs Detected:** {extracted_ips if extracted_ips else 'None'}")
        with col2:
            st.warning(f"**Parsed File Hashes Detected:** {extracted_hashes if extracted_hashes else 'None'}")

        with st.spinner("AI Agent orchestrating intelligence enrichment, MITRE mapping, and detection engineering..."):
            messages = [
                {
                    "role": "system",
                    "content": (
                        "You are an expert elite autonomous AI Cyber Threat Hunter and Detection Engineer. "
                        "Analyze the raw log input and extracted indicators, invoke tools across AbuseIPDB, VirusTotal, and AlienVault OTX, and synthesize telemetry. "
                        "Your final response MUST be formatted as a professional SOC Incident Briefing containing the following sections:\n"
                        "1. **Executive Summary & Risk Score** (Low/Medium/High/Critical)\n"
                        "2. **Indicator Breakdown** (Synthesized findings from APIs for the extracted IOCs)\n"
                        "3. **MITRE ATT&CK Framework Mapping** (Rendered as a Markdown table with columns: `Tactic`, `Technique ID`, `Technique Name`, and `Observed Behavioral Description`)\n"
                        "4. **Recommended Hunting & Remediation Actions**\n"
                        "5. **Actionable Detection Engineering** (Provide a valid, clean **Sigma Rule in YAML format** and a **Microsoft Sentinel KQL query**)"
                    )
                },
                {"role": "user", "content": f"Here is the raw log/ticket text to investigate:\n{user_query}\n\nDetected IPs: {extracted_ips}\nDetected Hashes: {extracted_hashes}"}
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

            # Save to session history
            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            st.session_state.history.append({
                "timestamp": timestamp,
                "query": user_query,
                "report": report_content
            })

    # Display Report
    st.subheader("AI Threat Hunter Briefing & Detection Report")
    st.markdown(report_content)

    # Download Report Button
    st.download_button(
        label="📥 Download Investigation Report (Markdown)",
        data=report_content,
        file_name=f"SOC_Threat_Report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.md",
        mime="text/markdown"
    )