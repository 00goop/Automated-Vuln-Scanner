"""
ML Model Trainer for Vulnerability Exploitability Prediction
Trains a Random Forest classifier targeting ~92% F1-score.
"""
import pandas as pd
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split, cross_val_score, GridSearchCV
from sklearn.metrics import (
    f1_score, precision_score, recall_score, accuracy_score,
    classification_report, confusion_matrix
)
from sklearn.preprocessing import StandardScaler
import joblib
from pathlib import Path
from typing import Dict, Tuple, Optional, Any
import json
import logging
from datetime import datetime

from .features import FeatureEngineer

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class VulnerabilityModelTrainer:
    """
    Trains and evaluates Random Forest model for vulnerability prioritization.
    Target: ~92% F1-score on exploitability prediction.
    """
    
    def __init__(self, model_dir: str = "./models"):
        self.model_dir = Path(model_dir)
        self.model_dir.mkdir(parents=True, exist_ok=True)
        
        self.feature_engineer = FeatureEngineer()
        self.model: Optional[RandomForestClassifier] = None
        self.scaler: Optional[StandardScaler] = None
        self.metrics: Dict[str, Any] = {}
        
    def prepare_training_data(
        self,
        cves: list,
        labels: Optional[list] = None
    ) -> Tuple[np.ndarray, np.ndarray]:
        """
        Prepare training data from CVE records.
        
        Args:
            cves: List of CVE dictionaries
            labels: Optional list of labels (1 = exploited, 0 = not exploited)
                    If not provided, synthetic labels are generated based on heuristics
            
        Returns:
            Tuple of (feature matrix, labels)
        """
        # Engineer features
        df = self.feature_engineer.engineer_features(cves)
        X = self.feature_engineer.get_feature_matrix(df)
        
        if labels is not None:
            y = np.array(labels)
        else:
            # Generate synthetic labels based on heuristics
            # This is used when real "exploited in the wild" data isn't available
            y = self._generate_synthetic_labels(df)
            logger.info("Generated synthetic labels based on vulnerability characteristics")
        
        return X, y
    
    def _generate_synthetic_labels(self, df: pd.DataFrame) -> np.ndarray:
        """
        Generate synthetic "exploited" labels based on heuristics.
        Used for training when real exploitation data isn't available.
        
        Heuristics:
        - Has known exploit + high CVSS = likely exploited
        - CVSS >= 8.0 + network vector + no auth = likely exploited
        - Old CVEs with patches = less likely exploited
        """
        labels = np.zeros(len(df), dtype=int)
        
        for i, row in df.iterrows():
            score = 0.0
            
            # Factor 1: Known exploit (strong signal)
            if row.get('has_exploit', 0) == 1:
                score += 0.4
            
            # Factor 2: High CVSS base score
            cvss = row.get('cvss_base_score', 5.0)
            if cvss >= 9.0:
                score += 0.3
            elif cvss >= 7.0:
                score += 0.2
            elif cvss >= 5.0:
                score += 0.1
            
            # Factor 3: Attack vector (network = easier to exploit remotely)
            if row.get('attack_vector_encoded', 0) == 3:  # NETWORK
                score += 0.15
            
            # Factor 4: No privileges required
            if row.get('privileges_required_encoded', 0) == 3:  # NONE
                score += 0.1
            
            # Factor 5: No user interaction
            if row.get('user_interaction_encoded', 0) == 2:  # NONE
                score += 0.1
            
            # Factor 6: Description severity
            desc_score = row.get('description_severity_score', 0.5)
            score += (desc_score - 0.5) * 0.2
            
            # Factor 7: Patch available reduces likelihood (attacker effort)
            if row.get('has_patch', 0) == 1:
                score -= 0.1
            
            # Factor 8: CWE category (injection/memory more exploited)
            cwe_cat = row.get('cwe_category_encoded', 0)
            if cwe_cat >= 7:  # injection or memory
                score += 0.1
            
            # Threshold with some randomness for realistic distribution
            threshold = 0.5 + np.random.normal(0, 0.05)
            labels[i] = 1 if score >= threshold else 0
        
        logger.info(f"Synthetic labels: {np.sum(labels)} positive / {len(labels)} total ({100*np.mean(labels):.1f}%)")
        return labels
    
    def train(
        self,
        X: np.ndarray,
        y: np.ndarray,
        test_size: float = 0.2,
        tune_hyperparameters: bool = True
    ) -> Dict[str, float]:
        """
        Train the Random Forest model.
        
        Args:
            X: Feature matrix
            y: Labels
            test_size: Fraction of data for testing
            tune_hyperparameters: Whether to perform grid search
            
        Returns:
            Dictionary of evaluation metrics
        """
        logger.info(f"Training on {len(y)} samples (positive rate: {np.mean(y):.2%})")
        
        # Split data
        X_train, X_test, y_train, y_test = train_test_split(
            X, y, test_size=test_size, stratify=y, random_state=42
        )
        
        # Scale features
        self.scaler = StandardScaler()
        X_train_scaled = self.scaler.fit_transform(X_train)
        X_test_scaled = self.scaler.transform(X_test)
        
        if tune_hyperparameters:
            logger.info("Tuning hyperparameters with grid search...")
            self.model = self._tune_hyperparameters(X_train_scaled, y_train)
        else:
            # Default parameters (known to work well)
            self.model = RandomForestClassifier(
                n_estimators=200,
                max_depth=15,
                min_samples_split=5,
                min_samples_leaf=2,
                class_weight='balanced',
                random_state=42,
                n_jobs=-1
            )
            self.model.fit(X_train_scaled, y_train)
        
        # Evaluate
        y_pred = self.model.predict(X_test_scaled)
        
        self.metrics = {
            'f1_score': float(f1_score(y_test, y_pred)),
            'precision': float(precision_score(y_test, y_pred)),
            'recall': float(recall_score(y_test, y_pred)),
            'accuracy': float(accuracy_score(y_test, y_pred)),
            'train_samples': len(y_train),
            'test_samples': len(y_test),
            'positive_rate': float(np.mean(y)),
            'trained_at': datetime.now().isoformat()
        }
        
        # Cross-validation F1 score
        cv_scores = cross_val_score(self.model, X_train_scaled, y_train, cv=5, scoring='f1')
        self.metrics['cv_f1_mean'] = float(np.mean(cv_scores))
        self.metrics['cv_f1_std'] = float(np.std(cv_scores))
        
        logger.info(f"Training complete!")
        logger.info(f"  F1 Score: {self.metrics['f1_score']:.2%}")
        logger.info(f"  Precision: {self.metrics['precision']:.2%}")
        logger.info(f"  Recall: {self.metrics['recall']:.2%}")
        logger.info(f"  CV F1: {self.metrics['cv_f1_mean']:.2%} ± {self.metrics['cv_f1_std']:.2%}")
        
        # Detailed report
        logger.info("\nClassification Report:")
        logger.info("\n" + classification_report(y_test, y_pred, target_names=['Not Exploited', 'Exploited']))
        
        return self.metrics
    
    def _tune_hyperparameters(self, X: np.ndarray, y: np.ndarray) -> RandomForestClassifier:
        """Perform grid search for optimal hyperparameters."""
        param_grid = {
            'n_estimators': [100, 200, 300],
            'max_depth': [10, 15, 20, None],
            'min_samples_split': [2, 5, 10],
            'min_samples_leaf': [1, 2, 4],
            'class_weight': ['balanced', 'balanced_subsample']
        }
        
        rf = RandomForestClassifier(random_state=42, n_jobs=-1)
        
        grid_search = GridSearchCV(
            rf, param_grid, cv=3, scoring='f1',
            n_jobs=-1, verbose=1
        )
        grid_search.fit(X, y)
        
        logger.info(f"Best parameters: {grid_search.best_params_}")
        logger.info(f"Best CV F1: {grid_search.best_score_:.2%}")
        
        return grid_search.best_estimator_
    
    def get_feature_importance(self) -> Dict[str, float]:
        """Get feature importance rankings."""
        if self.model is None:
            raise ValueError("Model not trained yet")
        
        importances = self.model.feature_importances_
        labels = self.feature_engineer.get_feature_importance_labels()
        
        importance_dict = dict(zip(labels, importances))
        # Sort by importance
        return dict(sorted(importance_dict.items(), key=lambda x: x[1], reverse=True))
    
    def save_model(self, filename: str = "rf_classifier.joblib") -> Path:
        """Save trained model and scaler."""
        if self.model is None:
            raise ValueError("Model not trained yet")
        
        model_path = self.model_dir / filename
        scaler_path = self.model_dir / "scaler.joblib"
        metrics_path = self.model_dir / "metrics.json"
        importance_path = self.model_dir / "feature_importance.json"
        
        joblib.dump(self.model, model_path)
        joblib.dump(self.scaler, scaler_path)
        
        with open(metrics_path, 'w') as f:
            json.dump(self.metrics, f, indent=2)
        
        with open(importance_path, 'w') as f:
            json.dump(self.get_feature_importance(), f, indent=2)
        
        logger.info(f"Model saved to {model_path}")
        return model_path
    
    def load_model(self, filename: str = "rf_classifier.joblib") -> None:
        """Load trained model and scaler."""
        model_path = self.model_dir / filename
        scaler_path = self.model_dir / "scaler.joblib"
        metrics_path = self.model_dir / "metrics.json"
        
        self.model = joblib.load(model_path)
        self.scaler = joblib.load(scaler_path)
        
        if metrics_path.exists():
            with open(metrics_path, 'r') as f:
                self.metrics = json.load(f)
        
        logger.info(f"Model loaded from {model_path}")


# CLI entry point
if __name__ == "__main__":
    import argparse
    import sys
    sys.path.insert(0, str(Path(__file__).parent.parent))
    
    from data.nvd_fetcher import NVDFetcher
    
    parser = argparse.ArgumentParser(description="Train vulnerability prediction model")
    parser.add_argument("--data", type=str, default="./data/cves.json", help="CVE data file")
    parser.add_argument("--evaluate", action="store_true", help="Only evaluate, don't save")
    parser.add_argument("--no-tune", action="store_true", help="Skip hyperparameter tuning")
    parser.add_argument("--test-only", action="store_true", help="Test existing model")
    args = parser.parse_args()
    
    trainer = VulnerabilityModelTrainer(model_dir="./models")
    
    if args.test_only:
        trainer.load_model()
        print(f"Loaded model metrics: {trainer.metrics}")
        print(f"Feature importance: {trainer.get_feature_importance()}")
    else:
        # Load CVE data
        fetcher = NVDFetcher(data_dir="./data")
        cves = fetcher.load_from_json(Path(args.data).name)
        
        if not cves:
            print("No CVE data found. Run nvd_fetcher.py first.")
            sys.exit(1)
        
        # Prepare and train
        X, y = trainer.prepare_training_data(cves)
        metrics = trainer.train(X, y, tune_hyperparameters=not args.no_tune)
        
        # Check F1 threshold
        if metrics['f1_score'] >= 0.92:
            print(f"\n✅ Model meets F1 threshold (>= 92%): {metrics['f1_score']:.2%}")
        else:
            print(f"\n⚠️ Model below F1 threshold: {metrics['f1_score']:.2%} (target: 92%)")
        
        if not args.evaluate:
            trainer.save_model()
            print("\n📊 Feature Importance:")
            for feature, importance in trainer.get_feature_importance().items():
                bar = "█" * int(importance * 50)
                print(f"  {feature:30} {importance:.3f} {bar}")
