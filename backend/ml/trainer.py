"""Deterministic synthetic experiments and explicit externally supplied labels."""
import argparse
import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path

import joblib
import numpy as np
from sklearn.dummy import DummyClassifier
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import confusion_matrix, f1_score, precision_score, recall_score
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler

from .features import FeatureEngineer

# Exclude every input used to construct the synthetic target. Use the same
# schema at inference; additional temporal audits are required for real labels.
EXCLUDED = {
    'has_exploit', 'cvss_base_score', 'attack_vector_encoded',
    'privileges_required_encoded', 'user_interaction_encoded',
    'description_severity_score', 'has_patch', 'cwe_category_encoded',
}


def selected_features(engineer):
    return [name for name in engineer.feature_names if name not in EXCLUDED]


def scores(y, predicted):
    return {
        'f1_score': float(f1_score(y, predicted, zero_division=0)),
        'precision': float(precision_score(y, predicted, zero_division=0)),
        'recall': float(recall_score(y, predicted, zero_division=0)),
        'confusion_matrix': confusion_matrix(y, predicted, labels=[0, 1]).tolist(),
    }


class VulnerabilityModelTrainer:
    def __init__(self, model_dir='./models', seed=42, as_of=None):
        self.model_dir = Path(model_dir)
        self.seed = seed
        self.as_of = as_of or datetime.now(timezone.utc)
        self.feature_engineer = FeatureEngineer(self.as_of)
        self.feature_names = selected_features(self.feature_engineer)
        self.model = None
        self.scaler = None
        self.metrics = {}
        self.label_source = 'unspecified'

    def prepare_training_data(self, cves, labels=None, *, synthetic=False):
        if not cves:
            raise ValueError('Training requires a nonempty dataset')
        ids = [cve.get('cve_id') if isinstance(cve, dict) else None for cve in cves]
        if any(not isinstance(cid, str) or not cid for cid in ids) or len(set(ids)) != len(ids):
            raise ValueError('Every training CVE must have a unique nonempty cve_id')
        df = self.feature_engineer.engineer_features(cves)
        if synthetic and labels is not None:
            raise ValueError('Choose synthetic or external labels, not both')
        if labels is None:
            if not synthetic:
                raise ValueError('External labels required; use synthetic=True for an experiment')
            self.label_source = 'synthetic_heuristic_experiment'
            rng = np.random.default_rng(self.seed)
            # A deliberately simple target; never a claim of exploitation truth.
            probability = np.clip(df['cvss_base_score'].to_numpy() / 10, 0, 1)
            y = (rng.random(len(df)) < probability).astype(int)
        else:
            self.label_source = 'externally_supplied_labels_unvalidated'
            y = np.asarray(labels)
            if y.shape != (len(df),) or not np.isin(y, [0, 1]).all():
                raise ValueError('One binary label is required per CVE')
        return df[self.feature_names].to_numpy(dtype=float), y

    def train(self, X, y, test_size=0.2, tune_hyperparameters=False):
        if tune_hyperparameters:
            raise ValueError('Automatic tuning is disabled; use a separately validated experiment')
        if self.label_source == 'unspecified':
            raise ValueError('Call prepare_training_data to establish label provenance first')
        if len(y) < 10 or len(np.unique(y)) != 2 or min(np.bincount(y.astype(int))) < 2:
            raise ValueError('Need at least ten samples and two examples of each class')
        train_x, test_x, train_y, test_y = train_test_split(
            X, y, test_size=test_size, stratify=y, random_state=self.seed)
        self.scaler = StandardScaler().fit(train_x)
        train_scaled = self.scaler.transform(train_x)
        test_scaled = self.scaler.transform(test_x)
        self.model = RandomForestClassifier(n_estimators=100, max_depth=10,
            min_samples_leaf=2, class_weight='balanced', random_state=self.seed, n_jobs=1)
        self.model.fit(train_scaled, train_y)
        baseline = DummyClassifier(strategy='most_frequent').fit(train_scaled, train_y)
        self.metrics = {
            **scores(test_y, self.model.predict(test_scaled)),
            'baseline': scores(test_y, baseline.predict(test_scaled)),
            'label_source': self.label_source, 'seed': self.seed,
            'as_of': self.as_of.isoformat(), 'feature_names': self.feature_names,
            'excluded_features': sorted(EXCLUDED), 'train_samples': len(train_y),
            'test_samples': len(test_y), 'class_distribution': np.bincount(y.astype(int), minlength=2).tolist(),
            'split': 'stratified random holdout; not prospective validation',
            'promotion_eligible': False,
        }
        return self.metrics

    def get_feature_importance(self):
        if self.model is None:
            raise ValueError('Model not trained')
        return dict(zip(self.feature_names, map(float, self.model.feature_importances_)))

    def save_model(self, filename='rf_classifier.joblib'):
        if self.model is None:
            raise ValueError('Model not trained')
        self.model_dir.mkdir(parents=True, exist_ok=True)
        path = self.model_dir / filename
        joblib.dump(self.model, path)
        joblib.dump(self.scaler, self.model_dir / 'scaler.joblib')
        for name, data in [('metrics.json', self.metrics), ('feature_importance.json', self.get_feature_importance())]:
            (self.model_dir / name).write_text(json.dumps(data, indent=2), encoding='utf-8')
        return path

    def load_model(self, filename='rf_classifier.joblib'):
        # Only load locally trusted joblib files: deserialization executes code.
        self.metrics = json.loads((self.model_dir / 'metrics.json').read_text())
        if self.metrics['feature_names'] != self.feature_names:
            raise ValueError('Incompatible feature schema; retrain the model')
        self.model = joblib.load(self.model_dir / filename)
        self.scaler = joblib.load(self.model_dir / 'scaler.joblib')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--data', default='./data/cves.json')
    parser.add_argument('--model-dir', default='./models')
    parser.add_argument('--synthetic', action='store_true')
    parser.add_argument('--labels', help='JSON object mapping every CVE ID to a binary external label')
    parser.add_argument('--seed', type=int, default=42)
    parser.add_argument('--as-of', help='ISO timestamp; defaults to dataset fetched_at')
    parser.add_argument('--no-tune', action='store_true', help='Compatibility flag; tuning is disabled')
    parser.add_argument('--evaluate', action='store_true', help='Evaluate without saving')
    args = parser.parse_args()
    raw = Path(args.data).read_bytes()
    dataset = json.loads(raw)
    cves = dataset['cves']
    as_of = args.as_of or dataset.get('fetched_at')
    if not as_of:
        parser.error('Provide --as-of or dataset fetched_at for reproducible age features')
    labels = None
    if args.labels:
        label_map = json.loads(Path(args.labels).read_text())
        labels = [label_map[cve['cve_id']] for cve in cves]
    trainer = VulnerabilityModelTrainer(args.model_dir, args.seed, datetime.fromisoformat(as_of))
    X, y = trainer.prepare_training_data(cves, labels, synthetic=args.synthetic)
    metrics = trainer.train(X, y)
    metrics['dataset_sha256'] = hashlib.sha256(raw).hexdigest()
    print(json.dumps(metrics, indent=2))
    if not args.evaluate:
        trainer.save_model()


if __name__ == '__main__':
    main()
