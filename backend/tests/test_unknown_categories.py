"""Preserve PR #1's unknown-category contract in the current CVE pipeline."""
import numpy as np
from ml.features import FeatureEngineer


def test_unseen_categories_use_finite_defaults_without_dropping_records():
    fields = (
        'attack_vector', 'attack_complexity', 'privileges_required',
        'user_interaction', 'confidentiality_impact', 'integrity_impact',
        'availability_impact',
    )
    engineer = FeatureEngineer()
    unknown = {'cve_id': 'CVE-DEMO-UNKNOWN', **dict.fromkeys(fields, 'NEW_CATEGORY')}
    missing = {'cve_id': 'CVE-DEMO-MISSING'}
    known = {'cve_id': 'CVE-DEMO-KNOWN', 'attack_vector': 'NETWORK'}
    frame = engineer.engineer_features([unknown, missing, known])
    matrix = engineer.get_feature_matrix(frame)
    assert frame.cve_id.tolist() == [unknown['cve_id'], missing['cve_id'], known['cve_id']]
    assert matrix.shape == (3, 17)
    assert np.isfinite(matrix).all()
    np.testing.assert_array_equal(matrix[0], matrix[1])
    assert frame.attack_vector_encoded.tolist() == [1, 1, 3]

