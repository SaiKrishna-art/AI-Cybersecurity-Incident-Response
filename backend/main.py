from fastapi import FastAPI
from pydantic import BaseModel
from threat_classifier import analyze_threat

app = FastAPI()

class ThreatRequest(BaseModel):
    threat_description: str
    source_ip: str = ""
    threat_type: str = ""

@app.get("/")
def root():
    return {"status": "AI Cybersecurity backend is running"}

@app.post("/analyze-threat")
def analyze(data: ThreatRequest):
    result = analyze_threat(
        threat_description=data.threat_description,
        source_ip=data.source_ip,
        threat_type=data.threat_type
    )
    return result