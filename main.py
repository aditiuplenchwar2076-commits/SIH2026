from fastapi import FastAPI, UploadFile, File
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

from vendor_detector import detect_vendor
from config_parser import parse_configuration
from security_rules import run_security_rules
from risk_score import calculate_risk_score
from ai_explainer import explain_findings


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


@app.post("/audit")
def audit(data: AuditRequest):

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

    return {
        "message": "Audit completed",
        "parsed_configuration": parsed_data,
        "findings": findings,
        "risk": risk,
        "ai_explanation": ai_explanation
    }


@app.post("/upload-config")
async def upload_config(file: UploadFile = File(...)):

    # Step 1: Read uploaded configuration file
    content = await file.read()

    # Step 2: Convert file into text
    configuration = content.decode("utf-8")

    # Step 3: Detect vendor automatically
    vendor = detect_vendor(configuration)

    # Step 4: Parse configuration
    parsed_data = parse_configuration(
        configuration,
        vendor
    )

    # Step 5: Run security rules
    findings = run_security_rules(parsed_data)

    # Step 6: Calculate risk score
    risk = calculate_risk_score(findings)

    # Step 7: Generate AI explanation
    ai_explanation = explain_findings(
        findings,
        vendor
    )

    return {
        "filename": file.filename,
        "vendor": vendor,
        "parsed_configuration": parsed_data,
        "findings": findings,
        "risk": risk,
        "ai_explanation": ai_explanation,
        "message": "Configuration audited successfully"
    }