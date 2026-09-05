def calculate_risk_score(findings):
    """
    Calculates an overall security score from 0 to 100.

    Higher score = more secure
    Lower score = more risky
    """

    score = 100

    high_count = 0
    medium_count = 0
    low_count = 0

    for finding in findings:

        severity = finding.get("severity", "").lower()

        if severity == "high":
            score -= 10
            high_count += 1

        elif severity == "medium":
            score -= 5
            medium_count += 1

        elif severity == "low":
            score -= 2
            low_count += 1

    # Score should never go below 0
    score = max(score, 0)

    # Determine overall risk level
    if score >= 80:
        risk_level = "Low"

    elif score >= 60:
        risk_level = "Medium"

    elif score >= 30:
        risk_level = "High"

    else:
        risk_level = "Critical"

    return {
        "security_score": score,
        "risk_level": risk_level,
        "high_findings": high_count,
        "medium_findings": medium_count,
        "low_findings": low_count
    }