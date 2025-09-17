import pandas as pd
from sklearn.preprocessing import LabelEncoder
from sklearn.ensemble import RandomForestClassifier
import joblib

# Load data
data = pd.read_csv('ml_data.csv')

# Encode categorical features
le_vuln = LabelEncoder(); data['vuln_type_enc'] = le_vuln.fit_transform(data['vuln_type'])
le_sev = LabelEncoder(); data['severity_enc'] = le_sev.fit_transform(data['severity'])
le_user = LabelEncoder(); data['user_input_enc'] = le_user.fit_transform(data['user_input'])
le_label = LabelEncoder(); data['exploit_enc'] = le_label.fit_transform(data['exploitability'])

# Features & labels
X = data[['vuln_type_enc','severity_enc','user_input_enc']]
y = data['exploit_enc']

# Train model
clf = RandomForestClassifier(n_estimators=50, random_state=42)
clf.fit(X, y)

# Save model and encoders
joblib.dump(clf, 'exploit_model.pkl')
joblib.dump(le_vuln, 'le_vuln.pkl')
joblib.dump(le_sev, 'le_sev.pkl')
joblib.dump(le_user, 'le_user.pkl')
joblib.dump(le_label, 'le_label.pkl')

print('ML model trained and saved!')
