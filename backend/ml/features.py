"""
Feature Engineering for CVE Vulnerability Prioritization
Transforms raw CVE data into ML-ready features (15+ engineered features).
"""
import pandas as pd
import numpy as np
from datetime import datetime
from typing import Dict, List, Optional, Any
import re
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


# Severity keywords for NLP-based scoring
CRITICAL_KEYWORDS = [
    'remote code execution', 'rce', 'arbitrary code', 'unauthenticated',
    'privilege escalation', 'root access', 'admin access', 'bypass authentication',
    'sql injection', 'command injection', 'buffer overflow', 'heap overflow',
    'use after free', 'zero-day', '0-day', 'actively exploited'
]

HIGH_KEYWORDS = [
    'denial of service', 'dos', 'information disclosure', 'sensitive data',
    'cross-site scripting', 'xss', 'csrf', 'path traversal', 'directory traversal',
    'ssrf', 'xml injection', 'ldap injection', 'memory corruption'
]

MEDIUM_KEYWORDS = [
    'limited impact', 'requires authentication', 'local access',
    'user interaction required', 'specific configuration'
]


class FeatureEngineer:
    """
    Engineers features from raw CVE data for ML model training.
    Produces 15+ features designed for exploitability prediction.
    """
    
    # Encoding maps for categorical features
    ATTACK_VECTOR_MAP = {
        'NETWORK': 3,
        'ADJACENT_NETWORK': 2,
        'LOCAL': 1,
        'PHYSICAL': 0,
        None: 1  # Default to LOCAL if unknown
    }
    
    ATTACK_COMPLEXITY_MAP = {
        'LOW': 2,
        'HIGH': 1,
        None: 1
    }
    
    PRIVILEGES_REQUIRED_MAP = {
        'NONE': 3,
        'LOW': 2,
        'HIGH': 1,
        None: 2
    }
    
    USER_INTERACTION_MAP = {
        'NONE': 2,
        'REQUIRED': 1,
        None: 1
    }
    
    IMPACT_MAP = {
        'HIGH': 3,
        'LOW': 2,
        'NONE': 1,
        None: 1
    }
    
    # CWE category groupings (top weakness categories)
    CWE_CATEGORIES = {
        'injection': ['CWE-78', 'CWE-79', 'CWE-89', 'CWE-94', 'CWE-917'],
        'memory': ['CWE-119', 'CWE-120', 'CWE-125', 'CWE-416', 'CWE-787'],
        'auth': ['CWE-287', 'CWE-306', 'CWE-862', 'CWE-863'],
        'crypto': ['CWE-295', 'CWE-310', 'CWE-327', 'CWE-330'],
        'exposure': ['CWE-200', 'CWE-209', 'CWE-532'],
        'path': ['CWE-22', 'CWE-23', 'CWE-36'],
        'config': ['CWE-16', 'CWE-284', 'CWE-732'],
        'deserialization': ['CWE-502'],
        'other': []  # Catch-all
    }
    
    def __init__(self, as_of=None):
        self.as_of = as_of or datetime.now().astimezone()
        self.feature_names = [
            'cvss_base_score',
            'cvss_exploitability_score',
            'cvss_impact_score',
            'attack_vector_encoded',
            'attack_complexity_encoded',
            'privileges_required_encoded',
            'user_interaction_encoded',
            'confidentiality_impact_encoded',
            'integrity_impact_encoded',
            'availability_impact_encoded',
            'days_since_published',
            'reference_count',
            'affected_product_count',
            'has_patch',
            'has_exploit',
            'description_severity_score',
            'cwe_category_encoded'
        ]
    
    def engineer_features(self, cves: List[Dict[str, Any]]) -> pd.DataFrame:
        """
        Transform raw CVE data into feature matrix.
        
        Args:
            cves: List of CVE dictionaries from NVD fetcher
            
        Returns:
            DataFrame with engineered features
        """
        if not isinstance(cves, list):
            raise ValueError('CVEs must be a list')
        logger.info(f"Engineering features for {len(cves)} CVEs")
        
        features = []
        for cve in cves:
            if not isinstance(cve, dict):
                raise ValueError('Each CVE must be an object')
            try:
                feature_row = self._engineer_single_cve(cve)
                feature_row['cve_id'] = cve.get('cve_id', '')
                features.append(feature_row)
            except Exception as e:
                raise ValueError('Malformed CVE features') from e
        
        df = pd.DataFrame(features, columns=[*self.feature_names, 'cve_id'])
        
        # Fill missing values with sensible defaults
        df = self._fill_missing_values(df)
        
        logger.info(f"Engineered {len(df)} feature rows with {len(self.feature_names)} features")
        return df
    
    def _engineer_single_cve(self, cve: Dict[str, Any]) -> Dict[str, Any]:
        """Engineer features for a single CVE."""
        features = {}
        
        # 1-3: CVSS Scores (direct)
        features['cvss_base_score'] = 5.0 if cve.get('cvss_base_score') is None else cve['cvss_base_score']
        features['cvss_exploitability_score'] = 2.0 if cve.get('cvss_exploitability_score') is None else cve['cvss_exploitability_score']
        features['cvss_impact_score'] = 2.0 if cve.get('cvss_impact_score') is None else cve['cvss_impact_score']
        
        # 4-7: Attack characteristics (encoded)
        features['attack_vector_encoded'] = self.ATTACK_VECTOR_MAP.get(
            cve.get('attack_vector'), 1
        )
        features['attack_complexity_encoded'] = self.ATTACK_COMPLEXITY_MAP.get(
            cve.get('attack_complexity'), 1
        )
        features['privileges_required_encoded'] = self.PRIVILEGES_REQUIRED_MAP.get(
            cve.get('privileges_required'), 2
        )
        features['user_interaction_encoded'] = self.USER_INTERACTION_MAP.get(
            cve.get('user_interaction'), 1
        )
        
        # 8-10: Impact metrics (encoded)
        features['confidentiality_impact_encoded'] = self.IMPACT_MAP.get(
            cve.get('confidentiality_impact'), 1
        )
        features['integrity_impact_encoded'] = self.IMPACT_MAP.get(
            cve.get('integrity_impact'), 1
        )
        features['availability_impact_encoded'] = self.IMPACT_MAP.get(
            cve.get('availability_impact'), 1
        )
        
        # 11: Days since published
        published = cve.get('published', '')
        if published:
            try:
                pub_date = datetime.fromisoformat(published.replace('Z', '+00:00'))
                features['days_since_published'] = max(0, (self.as_of.replace(tzinfo=None) - pub_date.replace(tzinfo=None)).days)
            except (ValueError, TypeError):
                features['days_since_published'] = 365  # Default to 1 year
        else:
            features['days_since_published'] = 365
        
        # 12-13: Metadata counts
        features['reference_count'] = cve.get('reference_count', 0)
        features['affected_product_count'] = cve.get('affected_product_count', 1)
        
        # 14-15: Boolean indicators
        features['has_patch'] = 1 if cve.get('has_patch') else 0
        features['has_exploit'] = 1 if cve.get('has_exploit') else 0
        
        # 16: NLP-based severity score from description
        description = cve.get('description', '')
        features['description_severity_score'] = self._score_description(description)
        
        # 17: CWE category encoding
        cwe_ids = cve.get('cwe_ids', [])
        features['cwe_category_encoded'] = self._encode_cwe_category(cwe_ids)
        
        return features
    
    def _score_description(self, description: str) -> float:
        """
        Score vulnerability description based on severity keywords.
        Returns a score from 0.0 to 1.0.
        """
        if not description:
            return 0.5
        
        description_lower = description.lower()
        score = 0.5  # Baseline
        
        # Check for critical keywords
        for keyword in CRITICAL_KEYWORDS:
            if keyword in description_lower:
                score += 0.15
        
        # Check for high severity keywords
        for keyword in HIGH_KEYWORDS:
            if keyword in description_lower:
                score += 0.08
        
        # Check for medium/mitigating keywords (reduce score)
        for keyword in MEDIUM_KEYWORDS:
            if keyword in description_lower:
                score -= 0.05
        
        # Clamp to [0, 1]
        return max(0.0, min(1.0, score))
    
    def _encode_cwe_category(self, cwe_ids: List[str]) -> int:
        """
        Encode CWE IDs into category indices.
        Higher index = generally more severe category.
        """
        if not cwe_ids:
            return 0
        
        # Priority order (higher = more likely to be exploited)
        category_priority = {
            'injection': 8,
            'memory': 7,
            'deserialization': 6,
            'auth': 5,
            'path': 4,
            'exposure': 3,
            'crypto': 2,
            'config': 1,
            'other': 0
        }
        
        max_priority = 0
        for cwe_id in cwe_ids:
            for category, cwes in self.CWE_CATEGORIES.items():
                if cwe_id in cwes:
                    max_priority = max(max_priority, category_priority[category])
                    break
        
        return max_priority
    
    def _fill_missing_values(self, df: pd.DataFrame) -> pd.DataFrame:
        """Fill missing values with sensible defaults."""
        defaults = {
            'cvss_base_score': 5.0,
            'cvss_exploitability_score': 2.0,
            'cvss_impact_score': 2.0,
            'attack_vector_encoded': 1,
            'attack_complexity_encoded': 1,
            'privileges_required_encoded': 2,
            'user_interaction_encoded': 1,
            'confidentiality_impact_encoded': 1,
            'integrity_impact_encoded': 1,
            'availability_impact_encoded': 1,
            'days_since_published': 365,
            'reference_count': 0,
            'affected_product_count': 1,
            'has_patch': 0,
            'has_exploit': 0,
            'description_severity_score': 0.5,
            'cwe_category_encoded': 0
        }
        
        for col, default in defaults.items():
            if col in df.columns:
                df[col] = pd.to_numeric(df[col], errors='coerce').replace([np.inf, -np.inf], np.nan).fillna(default)
        
        return df
    
    def get_feature_matrix(self, df: pd.DataFrame) -> np.ndarray:
        """Extract just the feature columns as a numpy array."""
        return df[self.feature_names].values
    
    def get_feature_importance_labels(self) -> List[str]:
        """Get human-readable feature labels for explainability."""
        return [
            "CVSS Base Score",
            "Exploitability Score",
            "Impact Score",
            "Attack Vector (Network=High)",
            "Attack Complexity (Low=High Risk)",
            "Privileges Required (None=High Risk)",
            "User Interaction (None=High Risk)",
            "Confidentiality Impact",
            "Integrity Impact",
            "Availability Impact",
            "Days Since Published",
            "Reference Count",
            "Affected Products",
            "Patch Available",
            "Known Exploit",
            "Description Severity",
            "CWE Category Risk"
        ]


# Utility function for quick feature engineering
def engineer_cve_features(cves: List[Dict]) -> pd.DataFrame:
    """Convenience function to engineer features from CVE list."""
    engineer = FeatureEngineer()
    return engineer.engineer_features(cves)
