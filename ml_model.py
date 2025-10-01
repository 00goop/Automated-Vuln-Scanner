import warnings

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import LabelEncoder


def _fit_encoder_with_unknown(values, unknown_token="Unknown"):
    """Fit a LabelEncoder that can safely encode unseen categories."""
    encoder = LabelEncoder()
    encoder.fit(values)

    if unknown_token not in encoder.classes_:
        encoder.classes_ = np.append(encoder.classes_, unknown_token)

    return encoder


def _encode_series(series, encoder, unknown_token="Unknown"):
    """Encode a categorical series, replacing unseen values with a fallback."""
    mapping = {label: idx for idx, label in enumerate(encoder.classes_)}
    encoded = series.map(mapping)

    if encoded.isna().any():
        warnings.warn(
            "Encountered categories unknown to the encoder during training; "
            f"falling back to '{unknown_token}'."
        )
        encoded = encoded.fillna(mapping[unknown_token])

    return encoded.astype(int)


data = pd.read_csv('ml_data.csv')

le_vuln = _fit_encoder_with_unknown(data['vuln_type'])
data['vuln_type_enc'] = _encode_series(data['vuln_type'], le_vuln)

le_sev = _fit_encoder_with_unknown(data['severity'])
data['severity_enc'] = _encode_series(data['severity'], le_sev)

le_user = _fit_encoder_with_unknown(data['user_input'])
data['user_input_enc'] = _encode_series(data['user_input'], le_user)

le_label = LabelEncoder()
data['exploit_enc'] = le_label.fit_transform(data['exploitability'])

X = data[['vuln_type_enc', 'severity_enc', 'user_input_enc']]
y = data['exploit_enc']

clf = RandomForestClassifier(n_estimators=50, random_state=42)
clf.fit(X, y)

joblib.dump(clf, 'exploit_model.pkl')
joblib.dump(le_vuln, 'le_vuln.pkl')
joblib.dump(le_sev, 'le_sev.pkl')
joblib.dump(le_user, 'le_user.pkl')
joblib.dump(le_label, 'le_label.pkl')

print('ML model trained and saved!')
