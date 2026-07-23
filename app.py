import os
import json
import httpx
from dotenv import load_dotenv
from openai import OpenAI
import streamlit as st

load_dotenv()
client = OpenAI()

st.set_page_config(page_title="AI SOC Threat Hunter", page_icon="🛡️", layout="wide")

st.title("🛡️ AI-Assisted SOC Threat Hunter Workbench")
st.markdown("Enter an incident prompt or paste suspicious indicators to trigger autonomous agent enrichment.")

user_query = st.text_area("Investigation Query / Log Artifacts:", "Can you cross-reference IP address 185.220.101.5 and file hash 44d88612fea8a8f36de82e1278abb02f?")

def check_abuse_ipdb(ip_address: str) -> str:
    api_key = os.getenv("ABUSEIPDB_API_KEY")
    url = "https://api.abuseipdb.com/api/v2/check"
    headers = {"Key": api_key, "Accept": "application/json"}
    params = {"ipAddress": ip_address, "maxAgeInDays": "90"}
    try:
        response = httpx.get(url, headers=headers, params=params, timeout=10)
        return json.dumps(response.json())
    except Exception as e:
        return json.dumps({"error": str(e)})

def check_virustotal_hash(file_hash: str) -> str:
    api_key = os.getenv("VIRUSTOTAL_API_KEY")
    url = f"https://www.virustotal.com/api/v3/files/{file_hash}"
    headers = {"x-apikey": api_key}
    try:
        response = httpx.get(url, headers=headers, timeout=10)
        return json.dumps(response.json())
    except Exception as e:
        return json.dumps({"error": str(e)})

available_tools = {
    "check_abuse_ipdb": check_abuse_ipdb,
    "check_virustotal_hash": check_virustotal_hash
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
    }
]

if st.button("Run Threat Hunt"):
    with st.spinner("AI Agent analyzing and querying security APIs..."):
        messages = [
            {
                "role": "system",
                "content": "You are an expert autonomous AI Cyber Threat Hunter. Analyze inputs, invoke tools, and synthesize reports."
            },
            {"role": "user", "content": user_query}
        ]
        
        response = client.chat.completions.create(
            model="gpt-4o",
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
            
            final_response = client.chat.completions.create(model="gpt-4o", messages=messages)
            st.subheader("AI Threat Hunter Briefing Report")
            st.markdown(final_response.choices[0].message.content)
        else:
            st.subheader("AI Response")
            st.write(response_message.content)