import os
from pathlib import Path
from reportlab.lib.pagesizes import A4
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Image, Table, TableStyle
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.lib.enums import TA_CENTER


def generate_audit_pdf(
    audit_id: str,
    vendor: str,
    security_score: int,
    findings: list,
    suggestions: list,
    qr_file: str,
    output_file: str = None
) -> str:
    """
    Generate a formatted PDF audit report using ReportLab.

    Contains:
    - Title: Network Security Audit Report
    - Basic Information (Audit ID, Vendor)
    - Security Score (/100)
    - Security Findings table with Severity
    - Suggestions / Remediation
    - Audit Verification QR code with explanatory text
    """
    if output_file is None:
        reports_dir = Path("reports")
        reports_dir.mkdir(parents=True, exist_ok=True)
        output_file = str(reports_dir / f"{audit_id}_Report.pdf")
    else:
        Path(output_file).parent.mkdir(parents=True, exist_ok=True)

    doc = SimpleDocTemplate(
        output_file,
        pagesize=A4,
        rightMargin=40,
        leftMargin=40,
        topMargin=40,
        bottomMargin=40
    )

    styles = getSampleStyleSheet()

    title_style = styles["Title"]
    title_style.alignment = TA_CENTER

    normal_style = styles["Normal"]
    heading2_style = styles["Heading2"]

    story = []

    # Title
    story.append(Paragraph("Network Security Audit Report", title_style))
    story.append(Spacer(1, 20))

    # Basic Information
    story.append(Paragraph("<b>Basic Information</b>", heading2_style))
    story.append(Paragraph(f"Audit ID: {audit_id}", normal_style))
    story.append(Paragraph(f"Vendor: {vendor}", normal_style))
    story.append(Spacer(1, 15))

    # Security Score
    story.append(Paragraph("<b>Security Score</b>", heading2_style))
    story.append(
        Paragraph(
            f"Overall Security Score: <b>{security_score}/100</b>",
            normal_style
        )
    )
    story.append(Spacer(1, 15))

    # Findings
    story.append(Paragraph("<b>Security Findings</b>", heading2_style))

    if findings:
        table_data = [[
            Paragraph("<b>Issue</b>", normal_style),
            Paragraph("<b>Severity</b>", normal_style)
        ]]

        for finding in findings:
            issue_text = finding.get("issue", "")
            severity_text = finding.get("severity", "")
            table_data.append([
                Paragraph(issue_text, normal_style),
                Paragraph(severity_text, normal_style)
            ])

        table = Table(table_data, colWidths=[360, 110])
        table.setStyle(
            TableStyle([
                ("BACKGROUND", (0, 0), (-1, 0), colors.lightgrey),
                ("GRID", (0, 0), (-1, -1), 0.5, colors.black),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("PADDING", (0, 0), (-1, -1), 6),
            ])
        )
        story.append(table)
    else:
        story.append(
            Paragraph("No security issues found.", normal_style)
        )

    story.append(Spacer(1, 15))

    # Suggestions / Remediation
    story.append(Paragraph("<b>Suggestions / Remediation</b>", heading2_style))

    if suggestions:
        for suggestion in suggestions:
            # &bull; or safe bullet representation
            story.append(
                Paragraph(f"&bull; {suggestion}", normal_style)
            )
    else:
        story.append(
            Paragraph("No specific remediations required.", normal_style)
        )

    story.append(Spacer(1, 20))

    # QR Code
    story.append(Paragraph("<b>Audit Verification QR</b>", heading2_style))
    story.append(Spacer(1, 10))

    if qr_file and os.path.exists(qr_file):
        qr_image = Image(qr_file, width=150, height=150)
        story.append(qr_image)

    story.append(Spacer(1, 10))
    story.append(
        Paragraph(
            f"Scan this QR code to identify audit {audit_id}.",
            normal_style
        )
    )

    doc.build(story)

    return output_file


if __name__ == "__main__":
    test_findings = [
        {"issue": "Telnet service enabled", "severity": "High"},
        {"issue": "Logging is disabled", "severity": "Medium"},
        {"issue": "SNMP public community detected", "severity": "High"}
    ]
    test_suggestions = [
        "Disable Telnet and use SSH.",
        "Enable proper system logging.",
        "Replace the default SNMP community string."
    ]

    from qr_generator import generate_audit_qr
    test_qr = generate_audit_qr("AUDIT-2026-0001")
    pdf = generate_audit_pdf(
        audit_id="AUDIT-2026-0001",
        vendor="Cisco",
        security_score=65,
        findings=test_findings,
        suggestions=test_suggestions,
        qr_file=test_qr
    )
    print(f"PDF generated successfully: {pdf}")
