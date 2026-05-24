from google import genai
import os
from dotenv import load_dotenv
import json
import requests

load_dotenv()

gemini_client = genai.Client(api_key=os.getenv("GEMINI_API_KEY"))
VIRUS_TOTAL_API_KEY = os.getenv("VIRUS_TOTAL_API_KEY")

def check_ip_virustotal(ip_address):
    try:
        url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip_address}"
        headers = {
            "x-apikey": VIRUS_TOTAL_API_KEY}
        response = requests.get(url, headers=headers)
        if response.status_code == 200:
            data = response.json()
            stats = data["data"]["attributes"]["last_analysis_stats"]
            malicious = stats.get("malicious", 0)
            suspicious = stats.get("suspicious", 0)
            return f"Malicious reports: {malicious}, Suspicious: {suspicious}"
        else:
            return "VirusTotal lookup unavailable"
    except Exception as e:
        return f"VirusTotal error: {str(e)}"
    
def analyze_threat(threat_description, source_ip="", threat_type=""):
    # VirusTotal IP check
    vt_result = ""
    if source_ip:
        vt_result = check_ip_virustotal(source_ip)

    prompt = f"""
You are a cybersecurity AI analyst working in a Security Operations Center (SOC).
Analyze the security threat below and return ONLY a valid JSON object.
No explanation. No markdown. No extra text. Just the JSON.

Required fields:
- threat_type (one of: Malware, Brute Force, Phishing, DDoS, Ransomware, Suspicious Login, Data Breach, Insider Threat, Unknown)
- severity (one of: Critical, High, Medium, Low)
- assignment_group (one of: SOC Team, Threat Response Team, Endpoint Security, Network Security)
- recommended_action (specific response steps, 2-3 sentences)
- ai_analysis (brief technical analysis of the threat, 2-3 sentences)

Threat Description: {threat_description}
Threat Type Reported: {threat_type}
Source IP: {source_ip}
VirusTotal Result: {vt_result}
"""

    response = gemini_client.models.generate_content(
        model="gemini-2.5-flash",
        contents=prompt
    )

    text = response.text.strip()
    text = text.replace("```json", "").replace("```", "").strip()
    result = json.loads(text)

    # Add VirusTotal result to response
    result["virustotal_result"] = vt_result

    return result