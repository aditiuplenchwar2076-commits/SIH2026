# SIH2026 Backend

AI-Driven Multi-Vendor Network Security Compliance Auditor

## Tech Stack

- Python
- FastAPI
- OpenAI API
- Pydantic

## Project Setup

### 1. Clone the project

Clone the GitHub repository and open the project folder in VS Code.

### 2. Create virtual environment

```bash
python -m venv venv
```

### 3. Activate virtual environment

Windows:

```bash
venv\Scripts\activate
```

### 4. Install dependencies

```bash
pip install -r requirements.txt
```

### 5. Configure environment variables

Create a `.env` file in the project root:

```text
OPENAI_API_KEY=your_api_key_here
```

Never upload the `.env` file to GitHub.

### 6. Start the backend

```bash
fastapi dev main.py
```

### 7. Open API documentation

Open:

```text
http://127.0.0.1:8000/docs
```

## Main API Endpoints

### GET `/`

Checks whether the backend is running.

### GET `/hello`

Test endpoint.

### POST `/audit`

Audits a configuration provided directly in the request.

### POST `/upload-config`

Uploads a network device configuration file and performs:

1. Vendor detection
2. Configuration parsing
3. Security rule checks
4. Risk score calculation
5. AI explanation

## Supported Vendors

- Cisco
- Juniper
- Fortinet

## Important

The security rules engine performs the actual vulnerability detection.

The AI component explains verified findings and provides recommendations.

If the AI service is unavailable, the security audit still returns the verified findings and risk score.