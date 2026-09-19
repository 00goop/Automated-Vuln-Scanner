from datetime import datetime, timezone
import json
import subprocess
import sys
from pathlib import Path
import numpy as np
import pytest
from ml.features import FeatureEngineer
from ml.trainer import VulnerabilityModelTrainer, EXCLUDED
from ml.predictor import VulnerabilityPredictor
from data.nvd_fetcher import NVDFetcher

AS_OF = datetime(2026, 1, 24, tzinfo=timezone.utc)


def records():
    return [{'cve_id': f'CVE-2025-{i:04d}', 'cvss_base_score': i % 11,
             'cvss_impact_score': i % 4, 'description': None,
             'published': '2025-01-01T00:00:00Z'} for i in range(100)]


def test_missing_and_zero_cvss():
    engineer = FeatureEngineer(AS_OF)
    frame = engineer.engineer_features([{}, {'cvss_base_score': 0}])
    assert frame.cvss_base_score.tolist() == [5, 0]
    assert np.isfinite(engineer.get_feature_matrix(frame)).all()
    assert engineer.get_feature_matrix(engineer.engineer_features([])).shape == (0, 17)


@pytest.mark.parametrize('data', [[None], [{'description': 123}], 'invalid'])
def test_malformed_does_not_silently_drop_rows(data):
    with pytest.raises(ValueError):
        FeatureEngineer().engineer_features(data)


def test_explicit_labels_and_duplicates(tmp_path):
    trainer = VulnerabilityModelTrainer(tmp_path)
    for data in [[], records()[:1] * 2]:
        with pytest.raises(ValueError):
            trainer.prepare_training_data(data, synthetic=True)
    with pytest.raises(ValueError):
        trainer.prepare_training_data(records())
    with pytest.raises(ValueError):
        trainer.prepare_training_data(records(), [1])


def test_determinism_baseline_serialization_and_inference(tmp_path):
    first = VulnerabilityModelTrainer(tmp_path, as_of=AS_OF)
    second = VulnerabilityModelTrainer(tmp_path / 'other', as_of=AS_OF)
    X, y = first.prepare_training_data(records(), synthetic=True)
    X2, y2 = second.prepare_training_data(records(), synthetic=True)
    np.testing.assert_array_equal(X, X2)
    np.testing.assert_array_equal(y, y2)
    assert not EXCLUDED.intersection(first.feature_names)
    assert first.train(X, y) == second.train(X2, y2)
    assert first.metrics['promotion_eligible'] is False
    assert len(first.metrics['confusion_matrix']) == 2
    assert 'baseline' in first.metrics
    first.save_model()
    second.model_dir = tmp_path
    second.load_model()
    np.testing.assert_array_equal(first.model.predict(first.scaler.transform(X)),
                                  second.model.predict(second.scaler.transform(X)))
    predictions = VulnerabilityPredictor(tmp_path).predict_batch(records()[:3])
    assert len(predictions) == 3
    assert all(0 <= p['priority_score'] <= 1 for p in predictions)
    assert all(p['model_mode'] == 'synthetic_heuristic_experiment' for p in predictions)


def test_cli_saves_to_requested_path(tmp_path):
    data = tmp_path / 'fixture.json'
    data.write_text(json.dumps({'cves': records(), 'fetched_at': AS_OF.isoformat()}))
    result = subprocess.run([sys.executable, '-m', 'ml.trainer', '--data', str(data),
        '--synthetic', '--model-dir', str(tmp_path / 'models')],
        cwd=Path(__file__).parents[1], capture_output=True, text=True)
    assert result.returncode == 0, result.stderr
    metrics = json.loads((tmp_path / 'models/metrics.json').read_text())
    assert len(metrics['dataset_sha256']) == 64
    assert (tmp_path / 'models/rf_classifier.joblib').exists()


def test_nvd_missing_cvss(tmp_path):
    fetcher = NVDFetcher(data_dir=tmp_path)
    assert fetcher._extract_cvss({'cvssMetricV31': []}) == {}
    assert fetcher._parse_cve({}) is None
    assert fetcher._parse_cve({'id': 'CVE-2025-1234'})['cvss_base_score'] is None


def test_zero_cvss_fallback(tmp_path):
    assert VulnerabilityPredictor(tmp_path).predict_single({'cvss_base_score': 0})['priority_score'] == 0
