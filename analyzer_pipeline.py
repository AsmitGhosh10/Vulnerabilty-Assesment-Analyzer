import os
import io
import json
import pandas as pd
from typing import List
from pydantic import BaseModel, Field
from google import genai
from google.genai import types

# =====================================================================
# 1. SYNTHETIC DATA & ASSET MAP (Defined first so nothing throws NameError!)
# =====================================================================

SAMPLE_NESSUS_CSV = """CVE_ID,CVSS_Score,Affected_Asset,Vulnerability_Name,Description
CVE-2023-38408,9.8,prod-auth-db-01.internal,OpenSSH Remote Code Execution,OpenSSH before 9.3p2 allows remote attackers to execute arbitrary commands via forwarded PKCS#11 provider.
CVE-2023-44487,7.5,api-gateway-02.internal,HTTP/2 Rapid Reset Attack,The HTTP/2 protocol allows a denial of service (server resource consumption) via stream cancellation.
CVE-2021-44228,10.0,legacy-test-server-01,Apache Log4j RCE,Apache Log4j2 <=2.14.1 JNDI features used in configuration do not protect against attacker controlled LDAP and other JNDI related endpoints.
CVE-2023-23397,9.8,finance-mail-srv-01,Microsoft Outlook Elevation of Privilege,NTLM hash leak vulnerability allowing privilege escalation without user interaction.
CVE-2022-0001,3.1,dev-workstation-14,Minor Information Disclosure,Low severity banner disclosure on internal development server.
"""

# Asset Criticality Scale (1 = Low Impact, 5 = Mission Critical)
ASSET_CRITICALITY_MAP = {
    "prod-auth-db-01.internal": 5,
    "finance-mail-srv-01": 5,
    "api-gateway-02.internal": 4,
    "legacy-test-server-01": 1,
    "dev-workstation-14": 2,
}

# =====================================================================
# 2. DATA MODELS & RISK CALCULATION
# =====================================================================

class NormalizedFinding(BaseModel):
    cve_id: str = Field(..., description="CVE Identifier")
    cvss_score: float = Field(..., description="Base CVSS Score (0.0 - 10.0)")
    asset: str = Field(..., description="Hostname or IP of affected asset")
    title: str = Field(..., description="Vulnerability Name")
    description: str = Field(..., description="Technical scanner description")
    asset_criticality: int = Field(default=3, description="Business criticality (1-5)")
    business_risk_score: float = Field(default=0.0, description="Weighted business priority score")

def calculate_business_risk(cvss: float, criticality: int) -> float:
    """
    Calculates a Business Risk Score (0.0 - 10.0) by weighting
    CVSS severity (60%) against Asset Criticality (40%).
    """
    weighted_cvss = cvss * 0.6
    weighted_criticality = (criticality / 5.0 * 10.0) * 0.4
    return round(weighted_cvss + weighted_criticality, 2)

def parse_and_normalize_csv(csv_content: str) -> List[NormalizedFinding]:
    """Parses raw CSV scanner output and calculates risk scores."""
    df = pd.read_csv(io.StringIO(csv_content))
    findings = []
    
    for _, row in df.iterrows():
        asset_name = str(row["Affected_Asset"]).strip()
        criticality = ASSET_CRITICALITY_MAP.get(asset_name, 3)
        cvss = float(row["CVSS_Score"])
        
        finding = NormalizedFinding(
            cve_id=str(row["CVE_ID"]).strip(),
            cvss_score=cvss,
            asset=asset_name,
            title=str(row["Vulnerability_Name"]).strip(),
            description=str(row["Description"]).strip(),
            asset_criticality=criticality,
            business_risk_score=calculate_business_risk(cvss, criticality)
        )
        findings.append(finding)
    
    # Sort findings descending by Business Risk Score
    findings.sort(key=lambda x: x.business_risk_score, reverse=True)
    return findings

# =====================================================================
# 3. GEMINI API GENERATIVE AI ENGINE
# =====================================================================

def generate_remediation_roadmap(findings: List[NormalizedFinding]) -> str:
    """Sends top risk findings to Gemini API to produce an executive report."""
    api_key = os.environ.get("GEMINI_API_KEY")
    if not api_key:
        raise ValueError("GEMINI_API_KEY environment variable is not set.")

    client = genai.Client(api_key=api_key)
    
    top_findings_payload = [f.model_dump() for f in findings[:5]]
    
    system_instruction = (
        "You are an expert Chief Information Security Officer (CISO) and Lead Security Architect. "
        "Your task is to translate technical vulnerability scanner reports into clear, actionable "
        "remediation roadmaps for technical teams and leadership."
    )
    
    prompt = f"""
    Analyze the following prioritized vulnerability scan findings:
    
    FINDINGS DATA (JSON):
    {json.dumps(top_findings_payload, indent=2)}
    
    Provide your response in cleanly formatted Markdown with these sections:
    
    1. ## Executive Summary
       - 2-3 sentence overview of business risk exposure.
       
    2. ## High Priority Threats Breakdown
       - Plain-language explainers for the top 3 items based on 'business_risk_score'.
       
    3. ## Step-by-Step Remediation Plan
       - Ordered, actionable fixes grouped by timeline (e.g., Immediate/24-Hour, 7-Day Patching).
    """

    response = client.models.generate_content(
        model='gemini-3.6-flash',
        contents=prompt,
        config=types.GenerateContentConfig(
            system_instruction=system_instruction,
            temperature=0.2,
        )
    )
    
    return response.text