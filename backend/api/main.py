"""
MR-ROBOT API
Comprehensive Security Toolkit: Vulnerability Prioritization, Code Analysis, Crypto, OSINT
"""
from fastapi import FastAPI, HTTPException, Query, BackgroundTasks, UploadFile, File, Form
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
from typing import List, Optional, Dict, Any
import asyncio
from pathlib import Path
import sys
import os

# Add parent to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))

from config import settings
from ml.predictor import VulnerabilityPredictor
from ml.features import FeatureEngineer
from data.nvd_fetcher import NVDFetcher
from api.chatbot import ShieldChatbot
from api.code_analysis import code_analyzer
from api.crypto_tools import crypto_tools
from api.osint_tools import osint_tools

# Initialize FastAPI app
app = FastAPI(
    title="🤖 MR-ROBOT API",
    description="Comprehensive Security Toolkit: Vulnerability Prioritization, Code Analysis, Crypto Tools, OSINT",
    version="2.0.0",
    docs_url="/docs",
    redoc_url="/redoc"
)

# CORS middleware for React frontend
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins_list,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Initialize services
predictor = VulnerabilityPredictor(model_dir=str(Path(__file__).parent.parent / "models"))
chatbot = ShieldChatbot(api_key=settings.gemini_api_key)
nvd_fetcher = NVDFetcher(api_key=settings.nvd_api_key, data_dir=str(Path(__file__).parent.parent / "data"))

# In-memory cache
vulnerability_cache: Dict[str, Dict] = {}


# ============================================================================
# Pydantic Models
# ============================================================================

class HealthResponse(BaseModel):
    status: str
    version: str
    modules: Dict[str, bool]


class VulnerabilityInput(BaseModel):
    cve_id: str
    description: Optional[str] = None
    cvss_base_score: Optional[float] = None
    attack_vector: Optional[str] = None
    has_patch: Optional[bool] = False
    has_exploit: Optional[bool] = False


class CodeAnalysisRequest(BaseModel):
    code: str
    filename: str = "code.py"
    language: Optional[str] = None


class CryptoRequest(BaseModel):
    text: str
    encoding: str
    key: Optional[str] = None


class HashRequest(BaseModel):
    text: str
    algorithm: str = "sha256"


class ChatMessage(BaseModel):
    message: str
    context: Optional[Dict[str, Any]] = None


# ============================================================================
# Health & Info Routes
# ============================================================================

@app.get("/", response_model=HealthResponse)
async def root():
    """Health check with module status."""
    return HealthResponse(
        status="operational",
        version="2.0.0",
        modules={
            "vuln_prioritizer": predictor.model is not None,
            "ai_chatbot": chatbot.model is not None,
            "code_analysis": True,
            "crypto_tools": True,
            "osint_tools": True
        }
    )


@app.get("/api/health")
async def health_check():
    """Detailed health check."""
    return {
        "status": "healthy",
        "name": "MR-ROBOT",
        "version": "2.0.0",
        "modules": {
            "vulnerability_prioritization": True,
            "code_analysis": True,
            "crypto_tools": True,
            "osint_tools": True,
            "ai_assistant": chatbot.model is not None
        }
    }


# ============================================================================
# Vulnerability Prioritization Routes (existing)
# ============================================================================

@app.post("/api/predict")
async def predict_vulnerability(vuln: VulnerabilityInput):
    """Predict priority for a vulnerability."""
    cve_dict = vuln.model_dump()
    prediction = predictor.predict_single(cve_dict)
    vulnerability_cache[vuln.cve_id] = {**cve_dict, **prediction}
    return prediction


@app.get("/api/security-score")
async def get_security_score():
    """Calculate overall security score."""
    if not vulnerability_cache:
        return {"score": 100, "label": "Excellent", "breakdown": {}, "total": 0}
    predictions = list(vulnerability_cache.values())
    return predictor.calculate_security_score(predictions)


@app.get("/api/vulnerabilities")
async def list_vulnerabilities(limit: int = Query(50, ge=1, le=200)):
    """List cached vulnerabilities."""
    vulns = list(vulnerability_cache.values())
    vulns.sort(key=lambda x: x.get('priority_score', 0), reverse=True)
    return {"total": len(vulns), "vulnerabilities": vulns[:limit]}


# ============================================================================
# Code Analysis Routes (NEW)
# ============================================================================

@app.post("/api/analyze/code")
async def analyze_code(request: CodeAnalysisRequest):
    """
    Analyze code for security vulnerabilities.
    Returns a security grade (A-F) with detailed findings.
    """
    result = await code_analyzer.analyze_code(
        code=request.code,
        filename=request.filename,
        language=request.language
    )
    return result


@app.post("/api/analyze/upload")
async def analyze_uploaded_file(file: UploadFile = File(...)):
    """
    Upload a file for security analysis.
    """
    content = await file.read()
    try:
        code = content.decode('utf-8')
    except UnicodeDecodeError:
        return {"success": False, "error": "File must be a text file"}
    
    result = await code_analyzer.analyze_code(
        code=code,
        filename=file.filename or "uploaded.py"
    )
    return result


# ============================================================================
# Crypto Tools Routes (NEW)
# ============================================================================

@app.post("/api/crypto/decode")
async def decode_text(request: CryptoRequest):
    """
    Decode text using specified encoding (base64, hex, rot13, etc.)
    """
    return crypto_tools.decode(request.text, request.encoding, request.key)


@app.post("/api/crypto/encode")
async def encode_text(request: CryptoRequest):
    """
    Encode text using specified encoding.
    """
    return crypto_tools.encode(request.text, request.encoding, request.key)


@app.post("/api/crypto/auto-decode")
async def auto_decode(text: str = Form(...)):
    """
    Automatically detect and decode text.
    """
    return crypto_tools.auto_decode(text)


@app.post("/api/crypto/identify-hash")
async def identify_hash(hash_string: str = Form(...)):
    """
    Identify the type of a hash.
    """
    return crypto_tools.identify_hash(hash_string)


@app.post("/api/crypto/hash")
async def generate_hash(request: HashRequest):
    """
    Generate hash of text.
    """
    return crypto_tools.generate_hash(request.text, request.algorithm)


@app.get("/api/crypto/encodings")
async def get_supported_encodings():
    """Get list of supported encodings."""
    return {"encodings": crypto_tools.get_supported_encodings()}


# ============================================================================
# OSINT Routes (NEW)
# ============================================================================

@app.get("/api/osint/domain/{domain}")
async def domain_lookup(domain: str):
    """
    Perform comprehensive domain lookup (WHOIS, DNS, IP).
    """
    return await osint_tools.domain_lookup(domain)


@app.get("/api/osint/ip/{ip}")
async def ip_lookup(ip: str):
    """
    Get information about an IP address (geolocation, ISP, etc.)
    """
    return await osint_tools.ip_lookup(ip)


@app.get("/api/osint/username/{username}")
async def username_search(
    username: str,
    platforms: Optional[str] = Query(None, description="Comma-separated platforms")
):
    """
    Search for username across social platforms.
    """
    platform_list = platforms.split(',') if platforms else None
    return await osint_tools.username_search(username, platform_list)


@app.get("/api/osint/subdomains/{domain}")
async def subdomain_enumeration(domain: str):
    """
    Enumerate subdomains for a domain.
    """
    return await osint_tools.subdomain_enum(domain)


# ============================================================================
# AI Chatbot Routes
# ============================================================================

@app.post("/api/chat")
async def chat_with_shield(message: ChatMessage):
    """Chat with the AI security assistant."""
    context = message.context or {}
    if 'security_score' not in context and vulnerability_cache:
        predictions = list(vulnerability_cache.values())
        context['security_score'] = predictor.calculate_security_score(predictions)
    response = chatbot.chat(message.message, context)
    return response


@app.post("/api/chat/reset")
async def reset_chat():
    """Reset conversation history."""
    chatbot.reset_conversation()
    return {"success": True}


# ============================================================================
# Data Sync Routes
# ============================================================================

sync_status = {"status": "idle", "cve_count": 0, "last_sync": None}


@app.get("/api/sync/status")
async def get_sync_status():
    """Get NVD sync status."""
    return sync_status


@app.post("/api/sync/trigger")
async def trigger_sync(background_tasks: BackgroundTasks, days: int = Query(7, ge=1, le=365)):
    """Trigger background NVD sync."""
    if sync_status["status"] == "running":
        raise HTTPException(status_code=409, detail="Sync already in progress")
    
    sync_status["status"] = "running"
    background_tasks.add_task(run_sync, days)
    return {"message": f"Sync started for last {days} days", "status": "running"}


async def run_sync(days: int):
    """Background NVD sync task."""
    global sync_status
    try:
        from datetime import datetime
        cves = await nvd_fetcher.fetch_cves(days_back=days, max_results=500)
        await nvd_fetcher.save_to_json(cves, "cves.json")
        
        for cve in cves:
            prediction = predictor.predict_single(cve)
            vulnerability_cache[cve['cve_id']] = {**cve, **prediction}
        
        sync_status["last_sync"] = datetime.now().isoformat()
        sync_status["cve_count"] = len(cves)
        sync_status["status"] = "completed"
    except Exception as e:
        sync_status["status"] = f"error: {str(e)}"


# ============================================================================
# Startup
# ============================================================================

@app.on_event("startup")
async def startup_event():
    """Load cached data on startup."""
    try:
        cves = nvd_fetcher.load_from_json("cves.json")
        if cves:
            for cve in cves:
                prediction = predictor.predict_single(cve)
                vulnerability_cache[cve['cve_id']] = {**cve, **prediction}
            print(f"✅ MR-ROBOT loaded {len(cves)} CVEs")
    except Exception as e:
        print(f"Note: No cached CVE data ({e})")


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host=settings.api_host, port=settings.api_port, reload=settings.debug)
