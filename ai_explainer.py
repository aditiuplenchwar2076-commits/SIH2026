"""
AI Explanation Module for SIH2026

PLANNED FUTURE ENHANCEMENT:
Real-time Generative AI explanation of verified security findings (via OpenAI / LLM)
is planned as a future enhancement for production deployments.

For the current MVP, external AI API calls are disabled to ensure deterministic,
fast, zero-cost, and offline-reliable audit execution. Verified rule-based
remediations and structured recommendations are generated directly from the
deterministic compliance engine without external API dependencies.
"""

import os
from typing import List, Dict, Any


def explain_findings(findings: List[Dict[str, Any]], vendor: str) -> Dict[str, Any]:
    """
    Returns recommendations and summary for verified security findings.

    For the current MVP, rule-based recommendations are extracted directly from
    the deterministic security findings without making external OpenAI calls.
    Preserves the 'ai_explanation' API contract for frontend integration.
    """

    # If there are no findings, no security issues were detected
    if not findings:
        return {
            "status": "success",
            "summary": f"No security issues were detected in the {vendor} configuration.",
            "recommendations": []
        }

    # Extract verified rule-based remediations from the findings
    recommendations = []
    for finding in findings:
        remediation = finding.get("remediation")
        if remediation and remediation not in recommendations:
            recommendations.append(remediation)

    # Return structured explanation preserving the existing API contract
    return {
        "status": "unavailable",
        "summary": (
            f"AI-powered dynamic explanation is a planned future enhancement. "
            f"Displaying {len(recommendations)} verified rule-based remediation recommendations for {vendor}."
        ),
        "recommendations": recommendations
    }