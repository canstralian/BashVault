
"""
CodeQL Analyzer Module
Integrates CodeQL security analysis into InfoGather
"""

import subprocess
import json
import os
import tempfile
from pathlib import Path


class CodeQLAnalyzer:
    def __init__(self, verbose=False):
        """
        Initialize CodeQL analyzer
        
        Args:
            verbose (bool): Enable verbose output
        """
        self.verbose = verbose
        self.codeql_rules_dir = Path(__file__).parent.parent / "codeql_rules"
        
    def analyze(self, target_path, language="javascript"):
        """
        Perform CodeQL analysis on target codebase
        
        Args:
            target_path (str): Path to target codebase
            language (str): Programming language (javascript, python, etc.)
            
        Returns:
            dict: CodeQL analysis results
        """
        results = {
            'target': target_path,
            'language': language,
            'vulnerabilities': [],
            'dependency_issues': [],
            'ai_model_issues': [],
            'summary': {
                'total_issues': 0,
                'critical': 0,
                'high': 0,
                'medium': 0,
                'low': 0
            }
        }
        
        try:
            if self.verbose:
                print(f"    [+] Starting CodeQL analysis on {target_path}")
            
            # Check if CodeQL is available
            if not self._check_codeql_available():
                if self.verbose:
                    print("    [WARNING] CodeQL not available, performing manual analysis")
                return self._manual_analysis(target_path, results)
            
            # Create CodeQL database
            db_path = self._create_codeql_database(target_path, language)
            
            # Run CodeQL queries
            results['dependency_issues'] = self._run_dependency_queries(db_path)
            results['ai_model_issues'] = self._run_ai_model_queries(db_path)
            
            # Combine all vulnerabilities
            all_vulns = results['dependency_issues'] + results['ai_model_issues']
            results['vulnerabilities'] = all_vulns
            
            # Calculate summary
            results['summary'] = self._calculate_summary(all_vulns)
            
            # Cleanup
            self._cleanup_database(db_path)
            
        except Exception as e:
            results['error'] = f"CodeQL analysis error: {str(e)}"
            if self.verbose:
                print(f"    [ERROR] {str(e)}")
        
        return results
    
    def _check_codeql_available(self):
        """Check if CodeQL CLI is available"""
        try:
            result = subprocess.run(['codeql', '--version'], 
                                  capture_output=True, text=True, timeout=10)
            return result.returncode == 0
        except:
            return False
    
    def _create_codeql_database(self, target_path, language):
        """Create CodeQL database for analysis"""
        with tempfile.TemporaryDirectory() as temp_dir:
            db_path = os.path.join(temp_dir, "codeql_db")
            
            cmd = [
                'codeql', 'database', 'create',
                db_path,
                '--language', language,
                '--source-root', target_path
            ]
            
            subprocess.run(cmd, check=True, capture_output=True)
            return db_path
    
    def _run_dependency_queries(self, db_path):
        """Run dependency confusion queries"""
        vulnerabilities = []
        
        try:
            query_file = self.codeql_rules_dir / "dependency_confusion.ql"
            if query_file.exists():
                cmd = [
                    'codeql', 'query', 'run',
                    str(query_file),
                    '--database', db_path,
                    '--output', 'dependency_results.json',
                    '--format', 'json'
                ]
                
                result = subprocess.run(cmd, capture_output=True, text=True)
                
                if result.returncode == 0 and os.path.exists('dependency_results.json'):
                    with open('dependency_results.json', 'r') as f:
                        results = json.load(f)
                        
                    for result in results.get('results', []):
                        vulnerabilities.append({
                            'type': 'Dependency Confusion',
                            'severity': 'High',
                            'file': result.get('file', ''),
                            'line': result.get('line', 0),
                            'description': result.get('message', ''),
                            'remediation': 'Use trusted package registries and implement package integrity checks'
                        })
                    
                    os.remove('dependency_results.json')
        
        except Exception as e:
            if self.verbose:
                print(f"    [ERROR] Dependency query error: {str(e)}")
        
        return vulnerabilities
    
    def _run_ai_model_queries(self, db_path):
        """Run AI model security queries"""
        vulnerabilities = []
        
        try:
            query_file = self.codeql_rules_dir / "poisoned_model_loading.ql"
            if query_file.exists():
                cmd = [
                    'codeql', 'query', 'run',
                    str(query_file),
                    '--database', db_path,
                    '--output', 'ai_model_results.json',
                    '--format', 'json'
                ]
                
                result = subprocess.run(cmd, capture_output=True, text=True)
                
                if result.returncode == 0 and os.path.exists('ai_model_results.json'):
                    with open('ai_model_results.json', 'r') as f:
                        results = json.load(f)
                        
                    for result in results.get('results', []):
                        vulnerabilities.append({
                            'type': 'Unsafe AI Model Loading',
                            'severity': 'Critical',
                            'file': result.get('file', ''),
                            'line': result.get('line', 0),
                            'description': result.get('message', ''),
                            'remediation': 'Disable trust_remote_code and enable signature verification'
                        })
                    
                    os.remove('ai_model_results.json')
        
        except Exception as e:
            if self.verbose:
                print(f"    [ERROR] AI model query error: {str(e)}")
        
        return vulnerabilities
    
    def _manual_analysis(self, target_path, results):
        """Perform manual analysis when CodeQL is not available"""
        vulnerabilities = []
        
        # Manual dependency confusion check
        vulnerabilities.extend(self._manual_dependency_check(target_path))
        
        # Manual AI model loading check
        vulnerabilities.extend(self._manual_ai_model_check(target_path))
        
        results['vulnerabilities'] = vulnerabilities
        results['summary'] = self._calculate_summary(vulnerabilities)
        
        return results
    
    def _manual_dependency_check(self, target_path):
        """Manual check for dependency confusion"""
        vulnerabilities = []
        
        try:
            # Check for .npmrc files
            for root, dirs, files in os.walk(target_path):
                if '.npmrc' in files:
                    npmrc_path = os.path.join(root, '.npmrc')
                    try:
                        with open(npmrc_path, 'r') as f:
                            content = f.read()
                            
                        if 'registry' in content:
                            lines = content.split('\n')
                            for i, line in enumerate(lines):
                                if line.strip().startswith('registry') and 'npmjs.org' not in line:
                                    vulnerabilities.append({
                                        'type': 'Dependency Confusion',
                                        'severity': 'High',
                                        'file': npmrc_path,
                                        'line': i + 1,
                                        'description': 'Custom or untrusted registry configuration detected',
                                        'remediation': 'Use official npm registry or verify custom registry security'
                                    })
                    except Exception:
                        continue
        
        except Exception as e:
            if self.verbose:
                print(f"    [ERROR] Manual dependency check error: {str(e)}")
        
        return vulnerabilities
    
    def _manual_ai_model_check(self, target_path):
        """Manual check for unsafe AI model loading"""
        vulnerabilities = []
        
        try:
            # Check Python files for transformers usage
            for root, dirs, files in os.walk(target_path):
                for file in files:
                    if file.endswith('.py'):
                        file_path = os.path.join(root, file)
                        try:
                            with open(file_path, 'r', encoding='utf-8') as f:
                                content = f.read()
                                lines = content.split('\n')
                            
                            for i, line in enumerate(lines):
                                if 'from_pretrained' in line and (
                                    'trust_remote_code=True' in line or
                                    'skip_validation=True' in line
                                ):
                                    vulnerabilities.append({
                                        'type': 'Unsafe AI Model Loading',
                                        'severity': 'Critical',
                                        'file': file_path,
                                        'line': i + 1,
                                        'description': 'AI model loading with disabled security checks',
                                        'remediation': 'Remove trust_remote_code=True and enable validation'
                                    })
                        except Exception:
                            continue
        
        except Exception as e:
            if self.verbose:
                print(f"    [ERROR] Manual AI model check error: {str(e)}")
        
        return vulnerabilities
    
    def _calculate_summary(self, vulnerabilities):
        """Calculate vulnerability summary statistics"""
        summary = {
            'total_issues': len(vulnerabilities),
            'critical': 0,
            'high': 0,
            'medium': 0,
            'low': 0
        }
        
        for vuln in vulnerabilities:
            severity = vuln.get('severity', 'Medium').lower()
            if severity in summary:
                summary[severity] += 1
        
        return summary
    
    def _cleanup_database(self, db_path):
        """Clean up CodeQL database"""
        try:
            if os.path.exists(db_path):
                import shutil
                shutil.rmtree(db_path)
        except:
            pass
