# 🤖 MR-ROBOT

> **Comprehensive Security Toolkit** - Vulnerability Prioritization, Code Analysis, Crypto Tools, OSINT


## 🎯 Overview

MR-ROBOT is an all-in-one security toolkit that combines:
- **ML-Powered Vulnerability Prioritization** - experimental CVE ranking; no validated exploitation prediction claim
- **Code Security Grader** - Upload code, get a security grade (A-F) with detailed findings
- **Crypto Tools** - Encode/decode, hash identification, cipher operations
- **OSINT Search** - Domain lookup, IP geolocation, username reconnaissance

## 🚀 Quick Start

### Backend

```bash
cd backend
py -3 -m venv venv
.\venv\Scripts\activate
pip install -r requirements.txt
# Add GEMINI_API_KEY to .env
python -m uvicorn api.main:app --host 0.0.0.0 --port 8000
```

### Frontend

```bash
cd frontend
npm install
npm run dev
```

Open **http://localhost:5173** for the dashboard and **http://localhost:8000/docs** for API docs.

## 🛠️ Modules

### 1. Vulnerability Prioritization
- Fetches CVEs from NVD
- Uses a seeded Random Forest experiment with nine retained features and an explicit baseline
- Priority levels: Critical → High → Moderate → Low → Monitor

### 2. Code Security Grader
- Upload or paste code
- Runs Bandit (Python) for security analysis
- Returns grade A-F with detailed findings
- Highlights line numbers and severity

### 3. Crypto Tools
| Tool | Features |
|------|----------|
| Decode/Encode | Base64, Hex, URL, ROT13, Binary, Atbash |
| Hash | MD5, SHA1, SHA256, SHA384, SHA512 |
| Cipher | Caesar (all shifts), XOR, Reverse |

### 4. OSINT Search
- **Domain Lookup**: WHOIS, DNS records, IP resolution
- **IP Lookup**: Geolocation, ISP, reverse DNS
- **Username Search**: Check 15+ platforms (GitHub, Twitter, etc.)
- **Subdomain Enum**: Find subdomains using common prefixes

## 📡 API Endpoints

| Category | Endpoint | Method |
|----------|----------|--------|
| Health | `/api/health` | GET |
| Vulnerabilities | `/api/predict` | POST |
| Code Analysis | `/api/analyze/code` | POST |
| Crypto | `/api/crypto/decode` | POST |
| Crypto | `/api/crypto/encode` | POST |
| Crypto | `/api/crypto/identify-hash` | POST |
| OSINT | `/api/osint/domain/{domain}` | GET |
| OSINT | `/api/osint/ip/{ip}` | GET |
| OSINT | `/api/osint/username/{username}` | GET |
| Chat | `/api/chat` | POST |

## 🔑 Environment Variables

```env
GEMINI_API_KEY=your_key_here    # Required for AI chat
NVD_API_KEY=optional           # Faster NVD data sync
DEBUG=true                      # Development mode
```

## 📁 Project Structure

```
MR-ROBOT/
├── backend/
│   ├── api/
│   │   ├── main.py           # FastAPI routes
│   │   ├── chatbot.py        # Gemini AI assistant
│   │   ├── code_analysis.py  # Bandit integration
│   │   ├── crypto_tools.py   # Encoding/hashing
│   │   └── osint_tools.py    # OSINT features
│   ├── ml/                   # ML pipeline
│   └── data/                 # NVD data
├── frontend/
│   └── src/
│       ├── App.jsx          # React dashboard
│       └── index.css        # Styling
└── .github/workflows/       # CI/CD
```

## 📄 License

MIT License - see [LICENSE](LICENSE) for details.

---

Built with 🤖 by security enthusiasts.

## Evaluation and verification

See [model methodology](docs/model-card.md) and [CI policy](docs/ci-policy.md).
Synthetic labels are not observed exploitation outcomes. The daily workflow stores
experiments without promoting a model or claiming real-world F1 performance.

```bash
python -m pip install -r backend/requirements-ml.txt pytest pytest-asyncio
python -m pytest backend/tests -q
cd frontend
npm ci
npm run lint
npm run build
```

Frontend deployment uses `frontend/.env.example` (`VITE_API_BASE_URL`). Set backend
`CORS_ORIGINS` to the deployed frontend origin. Provider keys stay in the backend.
The API cache is process-local; a restart clears analyzed vulnerabilities. Dashboard
API failures are shown explicitly and do not substitute invented security scores.
The distinct code, crypto, OSINT and chat screens live in `frontend/src/components/`;
their shared HTTP client lives in `frontend/src/services/api.js`.

## Ownership and limitations

Personal project maintained by Guttu Abajebel. This repository demonstrates security
tool integration and experimental ML evaluation, not a certified security audit.
The deployment check must be configured as required by branch protection/hosting
before it can gate an external release. Public deployment additionally needs
authentication, request quotas and review of outbound OSINT network access.
