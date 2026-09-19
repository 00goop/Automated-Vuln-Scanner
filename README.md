# MR-ROBOT

**A defensive security workbench for turning scattered signals into an inspectable review queue.**

MR-ROBOT brings CVE prioritization, Python static analysis, data transforms, and
open-source intelligence into one FastAPI and React workspace. The interface is
deliberately terse and operational: it identifies its data sources, reports when the
API is unavailable, and keeps experimental model output separate from verified facts.

| Module | What it does | Evidence source |
| --- | --- | --- |
| Vulnerability triage | Ranks CVEs and explains priority factors | NVD records + seeded Random Forest experiment |
| Source inspection | Grades pasted or uploaded Python | Bandit findings with severity and line context |
| Crypto tools | Encodes, decodes, hashes, and identifies input | Deterministic local transforms |
| OSINT | Looks up public domain, IP, and username signals | Explicit outbound queries from the API |

> The prioritizer is an engineering experiment trained on deterministic synthetic
> labels. Its score is a triage aid, not a validated probability of exploitation.

## Why this project exists

Security data is often presented as either raw output or an unexplained score.
MR-ROBOT makes the path between those two states visible. A reviewer can inspect the
source record, the retained features, the baseline comparison, and the limitations in
the [model card](docs/model-card.md).

## Quick start

### Backend

```bash
cd backend
py -3 -m venv venv
.\venv\Scripts\activate
pip install -r requirements.txt
# GEMINI_API_KEY is optional and enables the assistant panel
python -m uvicorn api.main:app --host 0.0.0.0 --port 8000
```

### Frontend

```bash
cd frontend
npm install
npm run dev
```

Open **http://localhost:5173** for the dashboard and **http://localhost:8000/docs** for API docs.

## Modules

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

## API endpoints

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

## Environment variables

```env
GEMINI_API_KEY=your_key_here    # Required for AI chat
NVD_API_KEY=optional           # Faster NVD data sync
DEBUG=true                      # Development mode
```

## Project structure

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
│       ├── App.jsx          # Workbench shell and CVE queue
│       ├── components/      # Code, crypto, OSINT, and chat modules
│       ├── services/        # Shared API client
│       └── index.css        # Responsive console visual system
└── .github/workflows/       # CI/CD
```

## License

MIT License - see [LICENSE](LICENSE) for details.

---

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
