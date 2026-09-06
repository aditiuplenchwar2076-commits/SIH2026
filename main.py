import os
from pathlib import Path
from typing import Optional, List, Dict, Any
from uuid import uuid4
from datetime import datetime

from fastapi import FastAPI, UploadFile, File, HTTPException, status, Depends
from fastapi.responses import FileResponse
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

from vendor_detector import detect_vendor
from config_parser import parse_configuration
from security_rules import run_security_rules
from risk_score import calculate_risk_score
from ai_explainer import explain_findings
from auth import verify_token
from qr_generator import generate_audit_qr
from pdf_report import generate_audit_pdf
from audit_history import save_audit_record, get_user_audit_history

ALLOWED_EXTENSIONS = {".txt", ".cfg", ".conf"}


app = FastAPI()
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:3000",
        "http://localhost:5173"
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


class AuditRequest(BaseModel):
    vendor: str
    device: str
    configuration: str


class AuditReportRequest(BaseModel):
    audit_id: Optional[str] = None
    vendor: str
    security_score: int
    findings: List[Dict[str, Any]] = Field(default_factory=list)
    suggestions: Optional[List[str]] = None


@app.get("/")
def home():
    return {
        "message": "SIH Backend is running"
    }


@app.get("/hello")
def hello():
    return {
        "message": "Hello Aditi"
    }


@app.get("/auth/me")
def get_current_user(user=Depends(verify_token)):
    return {
        "message": "Authentication successful",
        "uid": user["uid"],
        "email": user.get("email"),
        "phone_number": user.get("phone_number")
    }


@app.get("/audit/history")
def get_audit_history(user=Depends(verify_token)):
    user_id = user["uid"]
    history = get_user_audit_history(user_id)
    return {
        "message": "Audit history retrieved successfully",
        "total_records": len(history),
        "audits": history
    }


@app.post("/audit")
def audit(data: AuditRequest, user=Depends(verify_token)):

    # Step 1: Parse configuration
    parsed_data = parse_configuration(
        data.configuration,
        data.vendor
    )

    # Step 2: Run deterministic security rules
    findings = run_security_rules(parsed_data)

    # Step 3: Calculate risk score
    risk = calculate_risk_score(findings)

    # Step 4: Ask AI to explain the verified findings
    ai_explanation = explain_findings(
        findings,
        data.vendor
    )

    # Step 5: Save audit history record
    try:
        save_audit_record(
            user_id=user["uid"],
            user_email=user.get("email"),
            vendor=data.vendor,
            hostname=parsed_data.get("hostname"),
            security_score=risk["security_score"],
            risk_level=risk["risk_level"],
            findings=findings,
            risk_data=risk,
            filename=None
        )
    except Exception:
        pass

    return {
        "message": "Audit completed",
        "parsed_configuration": parsed_data,
        "findings": findings,
        "risk": risk,
        "ai_explanation": ai_explanation
    }


@app.post("/upload-config")
async def upload_config(file: UploadFile = File(...), user=Depends(verify_token)):

    # Step 1: Validate file extension (.txt, .cfg, .conf)
    filename = file.filename or ""
    _, ext = os.path.splitext(filename)
    if ext.lower() not in ALLOWED_EXTENSIONS:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Unsupported file type '{ext}'. Supported file types are: .txt, .cfg, .conf"
        )

    # Step 2: Read uploaded configuration file
    content = await file.read()
    if not content or not content.strip():
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="The uploaded configuration file is empty."
        )

    # Step 3: Convert file into text (handles UTF-8, UTF-8 with BOM, and fallback)
    try:
        configuration = content.decode("utf-8-sig")
    except UnicodeDecodeError:
        try:
            configuration = content.decode("latin-1")
        except Exception:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Unable to decode file. Please ensure the file is a valid text configuration."
            )

    # Step 4: Detect vendor automatically
    vendor = detect_vendor(configuration)

    # Step 5: Parse configuration
    parsed_data = parse_configuration(
        configuration,
        vendor
    )

    # Step 6: Run security rules
    findings = run_security_rules(parsed_data)

    # Step 7: Calculate risk score
    risk = calculate_risk_score(findings)

    # Step 8: Generate AI explanation
    ai_explanation = explain_findings(
        findings,
        vendor
    )

    # Step 9: Save audit history record
    try:
        save_audit_record(
            user_id=user["uid"],
            user_email=user.get("email"),
            vendor=vendor,
            hostname=parsed_data.get("hostname"),
            security_score=risk["security_score"],
            risk_level=risk["risk_level"],
            findings=findings,
            risk_data=risk,
            filename=file.filename
        )
    except Exception:
        pass

    return {
        "filename": file.filename,
        "vendor": vendor,
        "parsed_configuration": parsed_data,
        "findings": findings,
        "risk": risk,
        "ai_explanation": ai_explanation,
        "message": "Configuration audited successfully"
    }


@app.post("/audit/report")
def create_audit_report(data: AuditReportRequest, user=Depends(verify_token)):

    # Step 1: Assign or generate unique audit ID
    audit_id = data.audit_id or f"AUDIT-{datetime.now().strftime('%Y%m%d')}-{uuid4().hex[:6].upper()}"

    # Step 2: Resolve suggestions from input or extract from finding remediations
    suggestions = data.suggestions
    if suggestions is None or len(suggestions) == 0:
        suggestions = []
        for finding in data.findings:
            remediation = finding.get("remediation")
            if remediation and remediation not in suggestions:
                suggestions.append(remediation)

    # Step 3: Generate QR code containing only the audit ID
    qr_file = generate_audit_qr(audit_id)

    # Step 4: Generate PDF report
    pdf_filename = f"reports/{audit_id}_Report.pdf"
    pdf_file = generate_audit_pdf(
        audit_id=audit_id,
        vendor=data.vendor,
        security_score=data.security_score,
        findings=data.findings,
        suggestions=suggestions,
        qr_file=qr_file,
        output_file=pdf_filename
    )

    # Step 5: Return PDF report file
    return FileResponse(
        path=pdf_file,
        media_type="application/pdf",
        filename=f"{audit_id}_Report.pdf"
    )