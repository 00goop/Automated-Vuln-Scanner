"""
Vulnerability Predictor - Real-time inference service
Provides priority predictions with confidence scores and explanations.
"""
import numpy as np
import joblib
from pathlib import Path
from typing import Dict, List, Optional, Any, Tuple
import logging

from .features import FeatureEngineer
from .trainer import selected_features
import json
from datetime import datetime

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


# Priority level definitions for consumer-friendly output
PRIORITY_LEVELS = {
    'critical': {
        'threshold': 0.85,
        'label': 'Critical Priority',
        'color': '#DC2626',  # Red
        'icon': '🔴',
        'action': 'Fix immediately - review high-priority indicators'
    },
    'high': {
        'threshold': 0.65,
        'label': 'High Priority',
        'color': '#F97316',  # Orange
        'icon': '🟠',
        'action': 'Fix within 24-48 hours'
    },
    'moderate': {
        'threshold': 0.40,
        'label': 'Moderate Priority',
        'color': '#EAB308',  # Yellow
        'icon': '🟡',
        'action': 'Plan fix in next sprint'
    },
    'low': {
        'threshold': 0.20,
        'label': 'Low Priority',
        'color': '#3B82F6',  # Blue
        'icon': '🔵',
        'action': 'Address when convenient'
    },
    'monitor': {
        'threshold': 0.0,
        'label': 'Monitor Only',
        'color': '#6B7280',  # Gray
        'icon': '⚪',
        'action': 'No immediate action required'
    }
}


class VulnerabilityPredictor:
    """
    Real-time vulnerability priority prediction.
    Translates ML probabilities into consumer-friendly priority levels.
    """
    
    def __init__(self, model_dir: str = "./models"):
        self.model_dir = Path(model_dir)
        self.model = None
        self.scaler = None
        self.feature_engineer = FeatureEngineer()
        self.feature_importance = {}
        self._load_model()
    
    def _load_model(self):
        """Load trained model, scaler, and metadata."""
        model_path = self.model_dir / "rf_classifier.joblib"
        scaler_path = self.model_dir / "scaler.joblib"
        importance_path = self.model_dir / "feature_importance.json"
        
        self.model_metadata = {}
        metadata_path = self.model_dir / 'metrics.json'
        if model_path.exists() and metadata_path.exists():
            self.model_metadata = json.loads(metadata_path.read_text())
            if self.model_metadata.get('feature_names') != selected_features(self.feature_engineer):
                logger.warning('Incompatible legacy model; using heuristic fallback')
                return
            self.feature_engineer = FeatureEngineer(datetime.fromisoformat(self.model_metadata['as_of']))
            self.model = joblib.load(model_path)
            logger.info(f"Loaded model from {model_path}")
        else:
            logger.warning(f"No model found at {model_path}")
        
        if scaler_path.exists():
            self.scaler = joblib.load(scaler_path)
        
        if importance_path.exists():
            with open(importance_path, 'r') as f:
                self.feature_importance = json.load(f)
    
    def predict_single(self, cve: Dict[str, Any]) -> Dict[str, Any]:
        """
        Predict priority for a single CVE.
        
        Args:
            cve: CVE dictionary with vulnerability data
            
        Returns:
            Dictionary with priority prediction and explanation
        """
        if self.model is None:
            return self._fallback_prediction(cve)
        
        # Engineer features
        df = self.feature_engineer.engineer_features([cve])
        X = df[selected_features(self.feature_engineer)].to_numpy(dtype=float)
        
        if self.scaler:
            X = self.scaler.transform(X)
        
        # Get probability
        proba = self.model.predict_proba(X)[0][1]  # Probability of class 1 (exploited)
        
        # Determine priority level
        priority = self._probability_to_priority(proba)
        
        # Generate explanation
        explanation = self._generate_explanation(cve, df.iloc[0], proba)
        
        return {
            'cve_id': cve.get('cve_id', ''),
            'priority_score': float(proba),
            'priority_level': priority['label'],
            'priority_color': priority['color'],
            'priority_icon': priority['icon'],
            'recommended_action': priority['action'],
            'explanation': explanation,
            'confidence': 'Experimental score; not calibrated exploitation probability',
            'model_mode': self.model_metadata.get('label_source', 'unknown')
        }
    
    def predict_batch(self, cves: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Predict priorities for multiple CVEs.
        Returns sorted by priority (highest first).
        """
        predictions = [self.predict_single(cve) for cve in cves]
        
        # Sort by priority score (descending)
        predictions.sort(key=lambda x: x['priority_score'], reverse=True)
        
        return predictions
    
    def _probability_to_priority(self, proba: float) -> Dict[str, Any]:
        """Convert probability to priority level."""
        for level_name in ['critical', 'high', 'moderate', 'low', 'monitor']:
            level = PRIORITY_LEVELS[level_name]
            if proba >= level['threshold']:
                return level
        return PRIORITY_LEVELS['monitor']
    
    def _score_to_confidence(self, proba: float) -> str:
        """
        Convert probability to confidence statement.
        Consumer psychology: We avoid raw percentages.
        """
        if proba >= 0.90:
            return "Very high confidence"
        elif proba >= 0.75:
            return "High confidence"
        elif proba >= 0.50:
            return "Moderate confidence"
        elif proba >= 0.30:
            return "Some uncertainty"
        else:
            return "Lower certainty - monitor for changes"
    
    def _generate_explanation(
        self,
        cve: Dict[str, Any],
        features: Dict[str, Any],
        proba: float
    ) -> Dict[str, Any]:
        """
        Generate human-readable explanation for the prediction.
        Builds trust by showing why this ranking was assigned.
        """
        reasons_for = []  # Reasons increasing priority
        reasons_against = []  # Mitigating factors
        
        # Check high-impact factors
        if cve.get('has_exploit'):
            reasons_for.append("Known exploit code exists")
        
        cvss = cve.get('cvss_base_score') or 0
        if cvss >= 9.0:
            reasons_for.append(f"Critical severity (CVSS {cvss})")
        elif cvss >= 7.0:
            reasons_for.append(f"High severity (CVSS {cvss})")
        
        if cve.get('attack_vector') == 'NETWORK':
            reasons_for.append("Remotely exploitable (network attack)")
        
        if cve.get('privileges_required') == 'NONE':
            reasons_for.append("No authentication required")
        
        if cve.get('user_interaction') == 'NONE':
            reasons_for.append("No user interaction needed")
        
        # Check mitigating factors
        if cve.get('has_patch'):
            reasons_against.append("Patch is available")
        
        if cve.get('attack_complexity') == 'HIGH':
            reasons_against.append("High attack complexity")
        
        if cve.get('privileges_required') == 'HIGH':
            reasons_against.append("Requires high privileges")
        
        # CWE-based explanation
        cwe_ids = cve.get('cwe_ids', [])
        if cwe_ids:
            cwe_text = self._explain_cwe(cwe_ids[0])
            if cwe_text:
                reasons_for.append(cwe_text)
        
        return {
            'summary': self._generate_summary(proba, reasons_for),
            'factors_increasing_risk': reasons_for[:3],  # Top 3
            'mitigating_factors': reasons_against[:2],  # Top 2
            'top_contributing_features': self._get_top_features(features)
        }
    
    def _generate_summary(self, proba: float, reasons: List[str]) -> str:
        """Generate a one-sentence summary."""
        if proba >= 0.85:
            return f"This vulnerability has a high experimental priority score. {reasons[0] if reasons else 'Multiple high-risk factors detected.'}"
        elif proba >= 0.65:
            return f"This vulnerability poses significant risk. {reasons[0] if reasons else 'Several concerning factors detected.'}"
        elif proba >= 0.40:
            return f"This vulnerability has a moderate experimental priority score. Monitor and plan remediation."
        else:
            return "This vulnerability has a lower experimental priority score; this does not establish safety."
    
    def _explain_cwe(self, cwe_id: str) -> Optional[str]:
        """Provide human-readable CWE explanation."""
        cwe_explanations = {
            'CWE-79': 'Cross-site scripting (XSS) - commonly exploited',
            'CWE-89': 'SQL injection - frequently targeted',
            'CWE-78': 'OS command injection - high impact',
            'CWE-119': 'Buffer overflow - memory corruption risk',
            'CWE-416': 'Use after free - memory safety issue',
            'CWE-502': 'Unsafe deserialization - code execution risk',
            'CWE-287': 'Authentication bypass - access control failure',
        }
        return cwe_explanations.get(cwe_id)
    
    def _get_top_features(self, features: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Get top contributing features for this prediction."""
        if not self.feature_importance:
            return []
        
        feature_labels = self.feature_engineer.get_feature_importance_labels()
        feature_names = self.feature_engineer.feature_names
        
        top_features = []
        for i, (name, label) in enumerate(zip(feature_names, feature_labels)):
            if name in features:
                importance = self.feature_importance.get(name, 0)
                if importance > 0.05:  # Only show significant features
                    top_features.append({
                        'feature': label,
                        'importance': importance,
                        'value': features.get(name)
                    })
        
        return sorted(top_features, key=lambda x: x['importance'], reverse=True)[:5]
    
    def _fallback_prediction(self, cve: Dict[str, Any]) -> Dict[str, Any]:
        """
        Fallback prediction when model isn't available.
        Uses CVSS-based heuristics.
        """
        cvss = 5.0 if cve.get('cvss_base_score') is None else cve['cvss_base_score']
        
        # Simple CVSS-based scoring
        proba = min(1.0, cvss / 10.0 * 0.8)  # Scale CVSS to ~0.8 max
        
        if cve.get('has_exploit'):
            proba = min(1.0, proba + 0.15)
        
        priority = self._probability_to_priority(proba)
        
        return {
            'cve_id': cve.get('cve_id', ''),
            'priority_score': proba,
            'priority_level': priority['label'],
            'priority_color': priority['color'],
            'priority_icon': priority['icon'],
            'recommended_action': priority['action'],
            'explanation': {
                'summary': 'Prediction based on CVSS score (ML model not loaded)',
                'factors_increasing_risk': [],
                'mitigating_factors': [],
                'top_contributing_features': []
            },
            'confidence': 'Based on CVSS only'
        }
    
    def calculate_security_score(self, predictions: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Calculate overall security score (0-100) from predictions.
        Consumer psychology: A score to improve, not a count to fear.
        """
        if not predictions:
            return {'score': 100, 'label': 'Excellent', 'color': '#10B981'}
        
        # Weight by priority level
        weights = {
            'Critical Priority': 25,
            'High Priority': 15,
            'Moderate Priority': 8,
            'Low Priority': 3,
            'Monitor Only': 1
        }
        
        total_penalty = 0
        for pred in predictions:
            level = pred.get('priority_level', 'Monitor Only')
            total_penalty += weights.get(level, 1)
        
        # Score starts at 100 and decreases
        score = max(0, 100 - total_penalty)
        
        # Determine label
        if score >= 90:
            label, color = 'Excellent', '#10B981'  # Green
        elif score >= 75:
            label, color = 'Good', '#3B82F6'  # Blue
        elif score >= 50:
            label, color = 'Fair', '#EAB308'  # Yellow
        elif score >= 25:
            label, color = 'Poor', '#F97316'  # Orange
        else:
            label, color = 'Critical', '#DC2626'  # Red
        
        return {
            'score': score,
            'label': label,
            'color': color,
            'breakdown': {
                'critical': sum(1 for p in predictions if p['priority_level'] == 'Critical Priority'),
                'high': sum(1 for p in predictions if p['priority_level'] == 'High Priority'),
                'moderate': sum(1 for p in predictions if p['priority_level'] == 'Moderate Priority'),
                'low': sum(1 for p in predictions if p['priority_level'] == 'Low Priority'),
                'monitor': sum(1 for p in predictions if p['priority_level'] == 'Monitor Only'),
            },
            'total_vulnerabilities': len(predictions)
        }
