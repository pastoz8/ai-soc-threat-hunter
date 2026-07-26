import os
import json
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
st.markdown("Autonomous threat intelligence, **MITRE ATT&CK mapping**, and **Automated Detection Engineering** with Case Management.")

# --- SIDEBAR: CASE HISTORY ARCHIVE ---
st.sidebar.title("📁 Investigation Cases")
st.sidebar.markdown("Active session history of threat hunts:")

selected_case = None
if st.session_state.history:
    case_titles = [f"Case #{i+1}: {c['query'][:35]}..." for i, c in enumerate(st.session_state.history)]
    selected_index = st.sidebar.selectbox("Select Past Investigation", range(len(case_titles)), format_func=lambda x: case_titles[x])
    if st.sidebar.button("Load Selected Case"):
        selected_case = st.session_state.history[selected_index]
else:
    st.sidebar.info("No investigations logged in this session yet.")

if st.sidebar.button("Clear History"):
    st.session_state.history = []
    st.rerun()

# Main Input Form
default_query = selected_case["query"] if selected_case else "Can you cross-reference IP address 185.220.101.5, file hash 44d88612fea8a8f36de82e1278abb02f, map them to MITRE, and generate a Sigma rule?"
user_query = st.text_area("Investigation Query / Log Artifacts:", default_query)

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

if st.button("Run Threat Hunt & Generate Detection Rule") or selected_case:
    # If a past case was loaded from the sidebar, display it directly
    if selected_case and not st.session_state.get('just_ran', False):
        report_content = selected_case["report"]
        query_used = selected_case["query"]
    else:
        with st.spinner("AI Agent analyzing intelligence, mapping ATT&CK, and writing detection engineering rules..."):
            messages = [
                {
                    "role": "system",
                    "content": (
                        "You are an expert elite autonomous AI Cyber Threat Hunter and Detection Engineer. "
                        "Analyze analyst prompts, invoke tools across AbuseIPDB, VirusTotal, and AlienVault OTX, and synthesize telemetry. "
                        "Your final response MUST be formatted as a professional SOC Incident Briefing containing the following sections:\n"
                        "1. **Executive Summary & Risk Score** (Low/Medium/High/Critical)\n"
                        "2. **Indicator Breakdown** (Synthesized findings from APIs)\n"
                        "3. **MITRE ATT&CK Framework Mapping** (Rendered as a Markdown table with columns: `Tactic`, `Technique ID`, `Technique Name`, and `Observed Behavioral Description`)\n"
                        "4. **Recommended Hunting & Remediation Actions**\n"
                        "5. **Actionable Detection Engineering** (Provide a valid, clean **Sigma Rule in YAML format** and a **Microsoft Sentinel KQL query** designed to hunt for the investigated IOCs across enterprise telemetry)"
                    )
                },
                {"role": "user", "content": user_query}
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
            query_used = user_query

    # Display Report
    st.subheader(f"AI Threat Hunter Briefing Report")
    st.markdown(report_content)

    # Download Report Button
    st.download_button(
        label="📥 Download Investigation Report (Markdown)",
        data=report_content,
        file_name=f"SOC_Threat_Report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.md",
        mime="text/markdown"
    )