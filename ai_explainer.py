import os
from dotenv import load_dotenv
from openai import OpenAI

load_dotenv()


def explain_findings(findings, vendor):
    """
    Explains verified security findings using AI.

    If AI is unavailable, the security audit still works.
    """

    # If there are no findings, no AI explanation is needed
    if not findings:
        return {
            "status": "success",
            "summary": "No security issues were detected in the configuration.",
            "recommendations": []
        }

    # Get the API key from .env
    api_key = os.getenv("OPENAI_API_KEY")

    # If API key is missing, continue without AI
    if not api_key:
        return {
            "status": "unavailable",
            "summary": "AI explanation is not configured. Security findings and risk score are still available.",
            "recommendations": [
                finding.get("remediation")
                for finding in findings
            ]
        }

    client = OpenAI(api_key=api_key)

    # Prepare the verified findings for the AI
    findings_text = ""

    for finding in findings:
        findings_text += f"""
Rule ID: {finding.get("rule_id")}
Issue: {finding.get("issue")}
Severity: {finding.get("severity")}
Description: {finding.get("description")}
Remediation: {finding.get("remediation")}
"""

    prompt = f"""
You are a network security assistant helping analyze a {vendor} network device.

The security engine has already verified the findings below.

IMPORTANT:
- Do NOT invent additional vulnerabilities.
- Do NOT change the severity.
- Do NOT remove any verified finding.
- Only explain the findings provided.

For each finding:
1. Explain why it is a security risk in simple language.
2. Explain the potential impact.
3. Give a practical remediation recommendation.

Then provide a short overall security summary.

Verified findings:
{findings_text}
"""

    try:
        response = client.responses.create(
            model="gpt-5.6-luna",
            input=prompt
        )

        return {
            "status": "success",
            "summary": response.output_text,
            "recommendations": [
                finding.get("remediation")
                for finding in findings
            ]
        }

    except Exception:
        # AI failure should NOT break the security audit
        return {
            "status": "unavailable",
            "summary": "AI explanation is temporarily unavailable. The verified security findings and risk score are still available.",
            "recommendations": [
                finding.get("remediation")
                for finding in findings
            ]
        }