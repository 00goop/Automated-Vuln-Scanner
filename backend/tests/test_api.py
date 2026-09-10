import subprocess
from types import SimpleNamespace

import pytest
from fastapi.testclient import TestClient
from api.main import app
from api.code_analysis import CodeAnalyzer


def test_health_validation_and_zero_cvss():
    with TestClient(app) as client:
        assert client.get('/api/health').status_code == 200
        response = client.post('/api/predict', json={'cve_id': 'CVE-2026-12345', 'cvss_base_score': 0})
        assert response.status_code == 200
        assert response.json()['priority_score'] == 0
        assert client.post('/api/predict', json={'cve_id': '', 'cvss_base_score': 15}).status_code == 422
        assert client.post('/api/chat', json={'message': 'a' * 4001}).status_code == 422
        assert client.post('/api/analyze/upload', files={'file': ('large.py', b'x' * 100001)}).status_code == 413


@pytest.mark.asyncio
@pytest.mark.parametrize('result', [
    SimpleNamespace(stdout='broken json', returncode=1),
    SimpleNamespace(stdout='{"errors": [{"reason": "invalid syntax"}]}', returncode=1),
    SimpleNamespace(stdout='{}', returncode=2),
])
async def test_scanner_failure_is_not_grade_a(monkeypatch, tmp_path, result):
    monkeypatch.setattr(subprocess, 'run', lambda *args, **kwargs: result)
    response = await CodeAnalyzer(tmp_path).analyze_code('print(1)')
    assert response['success'] is False
    assert 'grade' not in response
