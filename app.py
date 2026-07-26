import os
import json
import httpx
from dotenv import load_dotenv
from openai import OpenAI
import streamlit as st

load_dotenv()
client = OpenAI()

st.set_page_config(page_title="AI SOC Threat Hunter Workbench", page_icon="🛡️", layout="wide")

st.title("🛡️ AI-Assisted SOC Threat Hunter Workbench")
st.markdown("Autonomous threat intelligence, **MITRE ATT&CK mapping**, and **Automated Detection Engineering**.")

user_query = st.text_area(
    "Investigation Query / Log Artifacts:", 
    "Can you cross-reference IP address 185.220.101.5, file hash 44d88612fea8a8f36de82e1278abb02f, map them to MITRE, and generate a Sigma rule?"
)

# --- HELPER: TRUNCATE LARGE TOOL RESPONSES ---
def truncate_json(data_str: str, max_chars: int = 4000) -> str:
    """Prevents TPM rate limit errors by trimming excessively large API json responses."""
    if len(data_str) > max_chars:
        return data_str[:max_chars] + "\n[TRUNCATED DUE TO SIZE]"
    return data_str

# --- SECURITY API TOOL DEFINITIONS ---

def check_abuse_ipdb(ip_address: str) -> str:
    """Query AbuseIPDB API to check reputation score and abuse confidence of an IP address."""
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
    """Query VirusTotal API to check file hash reputation and detection statistics."""
    api_key = os.getenv("VIRUSTOTAL_API_KEY")
    url = f"https://www.virustotal.com/api/v3/files/{file_hash}"
    headers = {"x-apikey": api_key}
    try:
        response = httpx.get(url, headers=headers, timeout=10)
        return truncate_json(json.dumps(response.json()))
    except Exception as e:
        return json.dumps({"error": str(e)})

def check_otx_indicator(indicator: str, indicator_type: str = "IPv4") -> str:
    """Query AlienVault OTX API to find community threat pulses associated with an IP, domain, or file hash."""
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

# --- OPENAI FUNCTION SCHEMAS ---

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

if st.button("Run Threat Hunt & Generate Detection Rule"):
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
            st.subheader("AI Threat Hunter Briefing, ATT&CK, & Detection Report")
            st.markdown(final_response.choices[0].message.content)
        else:
            st.subheader("AI Response")
            st.write(response_message.content)