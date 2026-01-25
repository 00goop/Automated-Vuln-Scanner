"""
MR-ROBOT Code Analysis Module
Upload and grade code for security vulnerabilities using Bandit.
"""
import os
import json
import tempfile
import subprocess
from pathlib import Path
from typing import Dict, Any, List, Optional
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


# Security grade thresholds
GRADE_THRESHOLDS = {
    'A': {'max_high': 0, 'max_medium': 0, 'max_low': 2},
    'B': {'max_high': 0, 'max_medium': 2, 'max_low': 5},
    'C': {'max_high': 1, 'max_medium': 5, 'max_low': 10},
    'D': {'max_high': 3, 'max_medium': 10, 'max_low': 20},
    'F': {'max_high': float('inf'), 'max_medium': float('inf'), 'max_low': float('inf')}
}

GRADE_COLORS = {
    'A': '#10B981',  # Green
    'B': '#3B82F6',  # Blue
    'C': '#EAB308',  # Yellow
    'D': '#F97316',  # Orange
    'F': '#DC2626',  # Red
}

GRADE_LABELS = {
    'A': 'Excellent - No significant security issues',
    'B': 'Good - Minor issues to address',
    'C': 'Fair - Several security concerns',
    'D': 'Poor - Significant security issues',
    'F': 'Critical - Major security vulnerabilities detected'
}


class CodeAnalyzer:
    """
    Analyzes code files for security vulnerabilities.
    """
    
    def __init__(self, upload_dir: str = "./uploads"):
        self.upload_dir = Path(upload_dir)
        self.upload_dir.mkdir(parents=True, exist_ok=True)
    
    async def analyze_code(
        self,
        code: str,
        filename: str = "code.py",
        language: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Analyze code string for security issues.
        
        Args:
            code: Source code as string
            filename: Original filename (for language detection)
            language: Optional language override
            
        Returns:
            Analysis results with grade and findings
        """
        # Detect language from filename
        if language is None:
            language = self._detect_language(filename)
        
        # Currently only Python is supported via Bandit
        if language != 'python':
            return {
                'success': False,
                'error': f'Language "{language}" not yet supported. Currently supporting: Python',
                'supported_languages': ['python']
            }
        
        # Write to temp file
        with tempfile.NamedTemporaryFile(
            mode='w', suffix='.py', delete=False
        ) as f:
            f.write(code)
            temp_path = f.name
        
        try:
            # Run Bandit analysis
            result = self._run_bandit(temp_path)
            
            # Calculate grade
            grade_info = self._calculate_grade(result['findings'])
            
            return {
                'success': True,
                'language': language,
                'grade': grade_info['grade'],
                'grade_color': grade_info['color'],
                'grade_label': grade_info['label'],
                'summary': {
                    'high_severity': result['counts']['high'],
                    'medium_severity': result['counts']['medium'],
                    'low_severity': result['counts']['low'],
                    'total_issues': result['counts']['total']
                },
                'findings': result['findings'][:20],  # Limit to top 20
                'scan_time': result.get('scan_time', 0)
            }
            
        finally:
            # Cleanup temp file
            if os.path.exists(temp_path):
                os.unlink(temp_path)
    
    def _detect_language(self, filename: str) -> str:
        """Detect programming language from filename."""
        ext_map = {
            '.py': 'python',
            '.js': 'javascript',
            '.ts': 'typescript',
            '.jsx': 'javascript',
            '.tsx': 'typescript',
            '.java': 'java',
            '.go': 'go',
            '.rb': 'ruby',
            '.php': 'php',
            '.c': 'c',
            '.cpp': 'cpp',
            '.cs': 'csharp',
            '.rs': 'rust',
        }
        
        ext = Path(filename).suffix.lower()
        return ext_map.get(ext, 'unknown')
    
    def _run_bandit(self, filepath: str) -> Dict[str, Any]:
        """Run Bandit security scanner on Python file."""
        try:
            result = subprocess.run(
                ['bandit', '-f', 'json', '-q', filepath],
                capture_output=True,
                text=True,
                timeout=30
            )
            
            # Parse JSON output (Bandit outputs to stdout even on findings)
            output = result.stdout if result.stdout else '{}'
            
            try:
                bandit_result = json.loads(output)
            except json.JSONDecodeError:
                bandit_result = {'results': [], 'metrics': {}}
            
            # Transform Bandit results to our format
            findings = []
            counts = {'high': 0, 'medium': 0, 'low': 0, 'total': 0}
            
            for issue in bandit_result.get('results', []):
                severity = issue.get('issue_severity', 'LOW').lower()
                finding = {
                    'severity': severity,
                    'confidence': issue.get('issue_confidence', 'LOW').lower(),
                    'title': issue.get('issue_text', 'Unknown issue'),
                    'test_id': issue.get('test_id', ''),
                    'test_name': issue.get('test_name', ''),
                    'line_number': issue.get('line_number', 0),
                    'line_range': issue.get('line_range', []),
                    'code_snippet': issue.get('code', ''),
                    'more_info': issue.get('more_info', '')
                }
                findings.append(finding)
                
                if severity == 'high':
                    counts['high'] += 1
                elif severity == 'medium':
                    counts['medium'] += 1
                else:
                    counts['low'] += 1
                counts['total'] += 1
            
            return {
                'findings': sorted(findings, key=lambda x: {'high': 0, 'medium': 1, 'low': 2}.get(x['severity'], 3)),
                'counts': counts,
                'scan_time': bandit_result.get('metrics', {}).get('_totals', {}).get('loc', 0)
            }
            
        except subprocess.TimeoutExpired:
            return {
                'findings': [],
                'counts': {'high': 0, 'medium': 0, 'low': 0, 'total': 0},
                'error': 'Analysis timed out'
            }
        except FileNotFoundError:
            # Bandit not installed - use fallback analysis
            return self._fallback_analysis(filepath)
    
    def _fallback_analysis(self, filepath: str) -> Dict[str, Any]:
        """Fallback pattern-based analysis when Bandit isn't available."""
        findings = []
        counts = {'high': 0, 'medium': 0, 'low': 0, 'total': 0}
        
        # Basic pattern matching for common issues
        patterns = [
            ('high', 'eval(', 'Use of eval() is dangerous - allows code injection'),
            ('high', 'exec(', 'Use of exec() is dangerous - allows code injection'),
            ('high', 'subprocess.call(.*shell=True', 'Shell injection risk with shell=True'),
            ('medium', 'pickle.load', 'Pickle can execute arbitrary code when loading'),
            ('medium', 'yaml.load(', 'Use yaml.safe_load() instead of yaml.load()'),
            ('medium', 'input(', 'input() in Python 2 can execute code'),
            ('low', 'assert ', 'Assert statements removed in production (-O flag)'),
            ('low', 'DEBUG = True', 'Debug mode should be disabled in production'),
            ('medium', 'password', 'Possible hardcoded password'),
            ('medium', 'secret', 'Possible hardcoded secret'),
            ('high', 'os.system(', 'os.system() is vulnerable to shell injection'),
        ]
        
        try:
            with open(filepath, 'r') as f:
                lines = f.readlines()
            
            for i, line in enumerate(lines, 1):
                for severity, pattern, message in patterns:
                    if pattern.lower() in line.lower():
                        findings.append({
                            'severity': severity,
                            'confidence': 'medium',
                            'title': message,
                            'test_id': 'PATTERN',
                            'test_name': 'pattern_match',
                            'line_number': i,
                            'line_range': [i],
                            'code_snippet': line.strip(),
                            'more_info': ''
                        })
                        counts[severity] += 1
                        counts['total'] += 1
                        
        except Exception as e:
            logger.error(f"Fallback analysis failed: {e}")
        
        return {
            'findings': sorted(findings, key=lambda x: {'high': 0, 'medium': 1, 'low': 2}.get(x['severity'], 3)),
            'counts': counts,
            'fallback': True
        }
    
    def _calculate_grade(self, findings: List[Dict]) -> Dict[str, Any]:
        """Calculate security grade based on findings."""
        counts = {'high': 0, 'medium': 0, 'low': 0}
        
        for finding in findings:
            severity = finding.get('severity', 'low')
            if severity in counts:
                counts[severity] += 1
        
        # Determine grade
        for grade in ['A', 'B', 'C', 'D', 'F']:
            thresholds = GRADE_THRESHOLDS[grade]
            if (counts['high'] <= thresholds['max_high'] and
                counts['medium'] <= thresholds['max_medium'] and
                counts['low'] <= thresholds['max_low']):
                return {
                    'grade': grade,
                    'color': GRADE_COLORS[grade],
                    'label': GRADE_LABELS[grade]
                }
        
        return {
            'grade': 'F',
            'color': GRADE_COLORS['F'],
            'label': GRADE_LABELS['F']
        }


# Export singleton
code_analyzer = CodeAnalyzer()
