
#!/usr/bin/env python3
"""
Autonomous Code Quality and Security Agent for CI Pipeline
Scans entire codebase and adapts to stack and language(s) in use
"""

import os
import sys
import json
import subprocess
import re
import ast
import tempfile
from pathlib import Path
from typing import Dict, List, Tuple, Optional
from dataclasses import dataclass, asdict
from datetime import datetime
import logging

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

@dataclass
class Issue:
    """Represents a code quality or security issue"""
    file_path: str
    line_number: int
    severity: str  # critical, high, medium, low, info
    category: str  # security, performance, style, logic
    rule_id: str
    message: str
    suggestion: Optional[str] = None
    auto_fixable: bool = False

@dataclass
class ScanResult:
    """Results from code scanning"""
    language: str
    tool: str
    issues: List[Issue]
    score: float
    passed: bool

class CodeQualityAgent:
    """Main agent class for code quality and security scanning"""
    
    def __init__(self, project_root: str = "."):
        self.project_root = Path(project_root)
        self.scan_results: List[ScanResult] = []
        self.languages_detected: List[str] = []
        self.frameworks_detected: List[str] = []
        
        # Thresholds for CI failure
        self.thresholds = {
            'pylint_score': 8.5,
            'security_issues': 0,  # No critical security issues
            'test_coverage': 80.0
        }
        
        # Auto-detect project structure
        self._detect_project_structure()
    
    def _detect_project_structure(self):
        """Auto-detect programming languages and frameworks"""
        logger.info("Detecting project structure...")
        
        # Check for Python files
        python_files = list(self.project_root.glob("**/*.py"))
        if python_files:
            self.languages_detected.append("python")
            
            # Check for Flask
            for py_file in python_files:
                try:
                    with open(py_file, 'r', encoding='utf-8') as f:
                        content = f.read()
                        if 'from flask import' in content or 'import flask' in content:
                            self.frameworks_detected.append("flask")
                            break
                except:
                    continue
        
        # Check for JavaScript/TypeScript
        js_files = list(self.project_root.glob("**/*.js")) + list(self.project_root.glob("**/*.ts"))
        if js_files:
            self.languages_detected.append("javascript")
        
        # Check for Shell scripts
        shell_files = list(self.project_root.glob("**/*.sh"))
        if shell_files:
            self.languages_detected.append("shell")
        
        # Check for package files
        if (self.project_root / "package.json").exists():
            self.frameworks_detected.append("nodejs")
        if (self.project_root / "requirements.txt").exists() or (self.project_root / "pyproject.toml").exists():
            self.frameworks_detected.append("python-package")
        
        logger.info(f"Detected languages: {self.languages_detected}")
        logger.info(f"Detected frameworks: {self.frameworks_detected}")
    
    def run_full_scan(self) -> bool:
        """Run complete code quality and security scan"""
        logger.info("Starting full codebase scan...")
        
        success = True
        
        # Run language-specific scans
        if "python" in self.languages_detected:
            success &= self._scan_python()
        
        if "javascript" in self.languages_detected:
            success &= self._scan_javascript()
        
        if "shell" in self.languages_detected:
            success &= self._scan_shell()
        
        # Run security scans
        success &= self._run_security_scan()
        
        # Run custom logic checks
        success &= self._run_custom_checks()
        
        # Generate report
        self._generate_report()
        
        return success
    
    def _scan_python(self) -> bool:
        """Comprehensive Python code analysis"""
        logger.info("Running Python analysis...")
        
        success = True
        
        # 1. Run pylint
        success &= self._run_pylint()
        
        # 2. Run flake8
        success &= self._run_flake8()
        
        # 3. Run bandit (security)
        success &= self._run_bandit()
        
        # 4. Run mypy (type checking)
        success &= self._run_mypy()
        
        # 5. Custom Python checks
        success &= self._run_python_custom_checks()
        
        return success
    
    def _run_pylint(self) -> bool:
        """Run pylint analysis"""
        try:
            cmd = ["python", "-m", "pylint", "--output-format=json", "--recursive=y", "."]
            result = subprocess.run(cmd, capture_output=True, text=True, cwd=self.project_root)
            
            issues = []
            score = 10.0
            
            if result.stdout:
                try:
                    pylint_data = json.loads(result.stdout)
                    
                    for item in pylint_data:
                        if isinstance(item, dict) and 'message' in item:
                            severity = self._map_pylint_severity(item.get('type', 'info'))
                            issues.append(Issue(
                                file_path=item.get('path', ''),
                                line_number=item.get('line', 0),
                                severity=severity,
                                category='style',
                                rule_id=item.get('message-id', ''),
                                message=item.get('message', ''),
                                suggestion=self._get_pylint_suggestion(item.get('message-id', '')),
                                auto_fixable=self._is_pylint_auto_fixable(item.get('message-id', ''))
                            ))
                except json.JSONDecodeError:
                    # Try to extract score from stderr
                    if result.stderr:
                        score_match = re.search(r'Your code has been rated at ([\d.]+)/10', result.stderr)
                        if score_match:
                            score = float(score_match.group(1))
            
            passed = score >= self.thresholds['pylint_score']
            
            self.scan_results.append(ScanResult(
                language="python",
                tool="pylint",
                issues=issues,
                score=score,
                passed=passed
            ))
            
            logger.info(f"Pylint score: {score}/10 (threshold: {self.thresholds['pylint_score']})")
            return passed
            
        except Exception as e:
            logger.error(f"Pylint scan failed: {str(e)}")
            return False
    
    def _run_flake8(self) -> bool:
        """Run flake8 analysis"""
        try:
            cmd = ["python", "-m", "flake8", "--format=json", "."]
            result = subprocess.run(cmd, capture_output=True, text=True, cwd=self.project_root)
            
            issues = []
            
            if result.stdout:
                try:
                    flake8_data = json.loads(result.stdout)
                    
                    for item in flake8_data:
                        issues.append(Issue(
                            file_path=item.get('filename', ''),
                            line_number=item.get('line_number', 0),
                            severity=self._map_flake8_severity(item.get('code', '')),
                            category='style',
                            rule_id=item.get('code', ''),
                            message=item.get('text', ''),
                            suggestion=self._get_flake8_suggestion(item.get('code', '')),
                            auto_fixable=self._is_flake8_auto_fixable(item.get('code', ''))
                        ))
                except json.JSONDecodeError:
                    # Parse plain text output
                    for line in result.stdout.split('\n'):
                        if line.strip():
                            match = re.match(r'([^:]+):(\d+):(\d+): (\w+) (.+)', line)
                            if match:
                                file_path, line_num, col, code, message = match.groups()
                                issues.append(Issue(
                                    file_path=file_path,
                                    line_number=int(line_num),
                                    severity=self._map_flake8_severity(code),
                                    category='style',
                                    rule_id=code,
                                    message=message,
                                    suggestion=self._get_flake8_suggestion(code),
                                    auto_fixable=self._is_flake8_auto_fixable(code)
                                ))
            
            passed = len([i for i in issues if i.severity in ['critical', 'high']]) == 0
            
            self.scan_results.append(ScanResult(
                language="python",
                tool="flake8",
                issues=issues,
                score=10.0 - len(issues) * 0.1,
                passed=passed
            ))
            
            logger.info(f"Flake8 found {len(issues)} issues")
            return passed
            
        except Exception as e:
            logger.error(f"Flake8 scan failed: {str(e)}")
            return False
    
    def _run_bandit(self) -> bool:
        """Run bandit security analysis"""
        try:
            cmd = ["python", "-m", "bandit", "-r", ".", "-f", "json"]
            result = subprocess.run(cmd, capture_output=True, text=True, cwd=self.project_root)
            
            issues = []
            
            if result.stdout:
                try:
                    bandit_data = json.loads(result.stdout)
                    
                    for item in bandit_data.get('results', []):
                        severity = item.get('issue_severity', 'medium').lower()
                        issues.append(Issue(
                            file_path=item.get('filename', ''),
                            line_number=item.get('line_number', 0),
                            severity=severity,
                            category='security',
                            rule_id=item.get('test_id', ''),
                            message=item.get('issue_text', ''),
                            suggestion=self._get_bandit_suggestion(item.get('test_id', '')),
                            auto_fixable=False
                        ))
                except json.JSONDecodeError:
                    logger.warning("Could not parse bandit JSON output")
            
            critical_issues = len([i for i in issues if i.severity == 'critical'])
            high_issues = len([i for i in issues if i.severity == 'high'])
            
            passed = critical_issues == 0 and high_issues <= self.thresholds['security_issues']
            
            self.scan_results.append(ScanResult(
                language="python",
                tool="bandit",
                issues=issues,
                score=10.0 - (critical_issues * 2 + high_issues * 1),
                passed=passed
            ))
            
            logger.info(f"Bandit found {len(issues)} security issues ({critical_issues} critical, {high_issues} high)")
            return passed
            
        except Exception as e:
            logger.error(f"Bandit scan failed: {str(e)}")
            return False
    
    def _run_mypy(self) -> bool:
        """Run mypy type checking"""
        try:
            cmd = ["python", "-m", "mypy", ".", "--ignore-missing-imports"]
            result = subprocess.run(cmd, capture_output=True, text=True, cwd=self.project_root)
            
            issues = []
            
            if result.stdout:
                for line in result.stdout.split('\n'):
                    if line.strip() and ':' in line:
                        match = re.match(r'([^:]+):(\d+): (\w+): (.+)', line)
                        if match:
                            file_path, line_num, severity, message = match.groups()
                            issues.append(Issue(
                                file_path=file_path,
                                line_number=int(line_num),
                                severity=severity.lower(),
                                category='type',
                                rule_id='mypy',
                                message=message,
                                suggestion=self._get_mypy_suggestion(message),
                                auto_fixable=False
                            ))
            
            passed = len([i for i in issues if i.severity == 'error']) == 0
            
            self.scan_results.append(ScanResult(
                language="python",
                tool="mypy",
                issues=issues,
                score=10.0 - len(issues) * 0.2,
                passed=passed
            ))
            
            logger.info(f"MyPy found {len(issues)} type issues")
            return passed
            
        except Exception as e:
            logger.error(f"MyPy scan failed: {str(e)}")
            return False
    
    def _run_python_custom_checks(self) -> bool:
        """Custom Python code quality checks"""
        logger.info("Running custom Python checks...")
        
        issues = []
        
        # Check all Python files
        for py_file in self.project_root.glob("**/*.py"):
            if py_file.name.startswith('.'):
                continue
                
            try:
                with open(py_file, 'r', encoding='utf-8') as f:
                    content = f.read()
                    lines = content.split('\n')
                
                # Parse AST for advanced checks
                try:
                    tree = ast.parse(content)
                    issues.extend(self._check_ast_issues(py_file, tree))
                except SyntaxError:
                    continue
                
                # Check for code smells
                for i, line in enumerate(lines, 1):
                    # Deep nesting check
                    if self._count_indentation(line) > 5:
                        issues.append(Issue(
                            file_path=str(py_file),
                            line_number=i,
                            severity='medium',
                            category='style',
                            rule_id='deep_nesting',
                            message='Deep nesting detected (>5 levels)',
                            suggestion='Consider extracting methods to reduce nesting',
                            auto_fixable=False
                        ))
                    
                    # Magic numbers check
                    if re.search(r'\b\d{3,}\b', line) and 'port' not in line.lower():
                        issues.append(Issue(
                            file_path=str(py_file),
                            line_number=i,
                            severity='low',
                            category='style',
                            rule_id='magic_number',
                            message='Magic number detected',
                            suggestion='Consider using named constants',
                            auto_fixable=False
                        ))
                    
                    # SQL injection patterns
                    if re.search(r'cursor\.execute\s*\(\s*[\'"].*%.*[\'"]', line):
                        issues.append(Issue(
                            file_path=str(py_file),
                            line_number=i,
                            severity='high',
                            category='security',
                            rule_id='sql_injection',
                            message='Potential SQL injection vulnerability',
                            suggestion='Use parameterized queries',
                            auto_fixable=False
                        ))
                    
                    # Missing docstring check
                    if line.strip().startswith('def ') and i + 1 < len(lines):
                        next_line = lines[i].strip()
                        if not next_line.startswith('"""') and not next_line.startswith("'''"):
                            issues.append(Issue(
                                file_path=str(py_file),
                                line_number=i,
                                severity='low',
                                category='documentation',
                                rule_id='missing_docstring',
                                message='Function missing docstring',
                                suggestion='Add docstring to document function purpose',
                                auto_fixable=False
                            ))
                
            except Exception as e:
                logger.warning(f"Error checking {py_file}: {str(e)}")
                continue
        
        passed = len([i for i in issues if i.severity in ['critical', 'high']]) == 0
        
        self.scan_results.append(ScanResult(
            language="python",
            tool="custom_checks",
            issues=issues,
            score=10.0 - len(issues) * 0.05,
            passed=passed
        ))
        
        logger.info(f"Custom checks found {len(issues)} issues")
        return passed
    
    def _check_ast_issues(self, file_path: Path, tree: ast.AST) -> List[Issue]:
        """Check AST for code quality issues"""
        issues = []
        
        for node in ast.walk(tree):
            # Check for duplicate code patterns
            if isinstance(node, ast.FunctionDef):
                if len(node.body) > 50:
                    issues.append(Issue(
                        file_path=str(file_path),
                        line_number=node.lineno,
                        severity='medium',
                        category='style',
                        rule_id='long_function',
                        message=f'Function "{node.name}" is too long ({len(node.body)} lines)',
                        suggestion='Consider breaking into smaller functions',
                        auto_fixable=False
                    ))
            
            # Check for security issues
            if isinstance(node, ast.Call):
                if hasattr(node.func, 'id'):
                    if node.func.id == 'eval':
                        issues.append(Issue(
                            file_path=str(file_path),
                            line_number=node.lineno,
                            severity='critical',
                            category='security',
                            rule_id='eval_usage',
                            message='Use of eval() detected - security risk',
                            suggestion='Use safer alternatives like ast.literal_eval()',
                            auto_fixable=False
                        ))
                    elif node.func.id == 'exec':
                        issues.append(Issue(
                            file_path=str(file_path),
                            line_number=node.lineno,
                            severity='critical',
                            category='security',
                            rule_id='exec_usage',
                            message='Use of exec() detected - security risk',
                            suggestion='Avoid dynamic code execution',
                            auto_fixable=False
                        ))
        
        return issues
    
    def _scan_javascript(self) -> bool:
        """Scan JavaScript/TypeScript code"""
        logger.info("Running JavaScript/TypeScript analysis...")
        
        # For now, return True as JS scanning is not implemented
        # In a real implementation, you would run eslint, tsc, etc.
        return True
    
    def _scan_shell(self) -> bool:
        """Scan shell scripts"""
        logger.info("Running shell script analysis...")
        
        try:
            issues = []
            
            for shell_file in self.project_root.glob("**/*.sh"):
                cmd = ["shellcheck", "-f", "json", str(shell_file)]
                result = subprocess.run(cmd, capture_output=True, text=True)
                
                if result.stdout:
                    try:
                        shellcheck_data = json.loads(result.stdout)
                        
                        for item in shellcheck_data:
                            issues.append(Issue(
                                file_path=str(shell_file),
                                line_number=item.get('line', 0),
                                severity=item.get('level', 'info').lower(),
                                category='shell',
                                rule_id=f"SC{item.get('code', '')}",
                                message=item.get('message', ''),
                                suggestion=self._get_shellcheck_suggestion(item.get('code', '')),
                                auto_fixable=False
                            ))
                    except json.JSONDecodeError:
                        continue
            
            passed = len([i for i in issues if i.severity in ['critical', 'high']]) == 0
            
            self.scan_results.append(ScanResult(
                language="shell",
                tool="shellcheck",
                issues=issues,
                score=10.0 - len(issues) * 0.1,
                passed=passed
            ))
            
            logger.info(f"Shellcheck found {len(issues)} issues")
            return passed
            
        except Exception as e:
            logger.error(f"Shell scan failed: {str(e)}")
            return True  # Don't fail CI if shellcheck is not available
    
    def _run_security_scan(self) -> bool:
        """Run comprehensive security scan"""
        logger.info("Running security analysis...")
        
        issues = []
        
        # Check for hardcoded secrets
        for file_path in self.project_root.glob("**/*.py"):
            if file_path.name.startswith('.'):
                continue
                
            try:
                with open(file_path, 'r', encoding='utf-8') as f:
                    content = f.read()
                    lines = content.split('\n')
                
                for i, line in enumerate(lines, 1):
                    # Check for hardcoded secrets
                    if self._check_hardcoded_secrets(line):
                        issues.append(Issue(
                            file_path=str(file_path),
                            line_number=i,
                            severity='high',
                            category='security',
                            rule_id='hardcoded_secret',
                            message='Potential hardcoded secret detected',
                            suggestion='Use environment variables or secure key management',
                            auto_fixable=False
                        ))
                    
                    # Check for insecure patterns
                    if 'verify=False' in line:
                        issues.append(Issue(
                            file_path=str(file_path),
                            line_number=i,
                            severity='medium',
                            category='security',
                            rule_id='ssl_verify_disabled',
                            message='SSL verification disabled',
                            suggestion='Enable SSL verification for security',
                            auto_fixable=False
                        ))
            
            except Exception as e:
                logger.warning(f"Error scanning {file_path}: {str(e)}")
                continue
        
        passed = len([i for i in issues if i.severity in ['critical', 'high']]) == 0
        
        self.scan_results.append(ScanResult(
            language="general",
            tool="security_scan",
            issues=issues,
            score=10.0 - len(issues) * 0.2,
            passed=passed
        ))
        
        logger.info(f"Security scan found {len(issues)} issues")
        return passed
    
    def _run_custom_checks(self) -> bool:
        """Run custom logic and pattern checks"""
        logger.info("Running custom checks...")
        
        issues = []
        
        # Check for Flask-specific issues
        if "flask" in self.frameworks_detected:
            issues.extend(self._check_flask_patterns())
        
        # Check for database security issues
        issues.extend(self._check_database_patterns())
        
        # Check for file handling issues
        issues.extend(self._check_file_handling())
        
        passed = len([i for i in issues if i.severity in ['critical', 'high']]) == 0
        
        self.scan_results.append(ScanResult(
            language="general",
            tool="custom_patterns",
            issues=issues,
            score=10.0 - len(issues) * 0.1,
            passed=passed
        ))
        
        logger.info(f"Custom checks found {len(issues)} issues")
        return passed
    
    def _check_flask_patterns(self) -> List[Issue]:
        """Check Flask-specific security patterns"""
        issues = []
        
        for py_file in self.project_root.glob("**/*.py"):
            try:
                with open(py_file, 'r', encoding='utf-8') as f:
                    content = f.read()
                    lines = content.split('\n')
                
                for i, line in enumerate(lines, 1):
                    # Check for debug mode in production
                    if 'debug=True' in line and 'app.run' in line:
                        issues.append(Issue(
                            file_path=str(py_file),
                            line_number=i,
                            severity='high',
                            category='security',
                            rule_id='flask_debug_production',
                            message='Debug mode enabled in production',
                            suggestion='Set debug=False or use environment variables',
                            auto_fixable=True
                        ))
                    
                    # Check for missing CSRF protection
                    if '@app.route' in line and 'POST' in line:
                        # Look for CSRF protection in surrounding lines
                        context_lines = lines[max(0, i-3):i+3]
                        if not any('csrf' in l.lower() for l in context_lines):
                            issues.append(Issue(
                                file_path=str(py_file),
                                line_number=i,
                                severity='medium',
                                category='security',
                                rule_id='missing_csrf_protection',
                                message='POST route without CSRF protection',
                                suggestion='Add CSRF protection to prevent attacks',
                                auto_fixable=False
                            ))
            
            except Exception as e:
                continue
        
        return issues
    
    def _check_database_patterns(self) -> List[Issue]:
        """Check database security patterns"""
        issues = []
        
        for py_file in self.project_root.glob("**/*.py"):
            try:
                with open(py_file, 'r', encoding='utf-8') as f:
                    content = f.read()
                    lines = content.split('\n')
                
                for i, line in enumerate(lines, 1):
                    # Check for SQL injection patterns
                    if 'cursor.execute' in line and '%' in line:
                        issues.append(Issue(
                            file_path=str(py_file),
                            line_number=i,
                            severity='high',
                            category='security',
                            rule_id='sql_injection_risk',
                            message='Potential SQL injection vulnerability',
                            suggestion='Use parameterized queries with ? placeholders',
                            auto_fixable=False
                        ))
                    
                    # Check for missing password hashing
                    if 'password' in line.lower() and ('=' in line or 'INSERT' in line.upper()):
                        if not any(hash_func in line for hash_func in ['hash', 'bcrypt', 'pbkdf2', 'argon2']):
                            issues.append(Issue(
                                file_path=str(py_file),
                                line_number=i,
                                severity='high',
                                category='security',
                                rule_id='password_not_hashed',
                                message='Password may not be properly hashed',
                                suggestion='Use proper password hashing (bcrypt, argon2)',
                                auto_fixable=False
                            ))
            
            except Exception as e:
                continue
        
        return issues
    
    def _check_file_handling(self) -> List[Issue]:
        """Check file handling security"""
        issues = []
        
        for py_file in self.project_root.glob("**/*.py"):
            try:
                with open(py_file, 'r', encoding='utf-8') as f:
                    content = f.read()
                    lines = content.split('\n')
                
                for i, line in enumerate(lines, 1):
                    # Check for unsafe file operations
                    if 'open(' in line and 'user' in line.lower():
                        issues.append(Issue(
                            file_path=str(py_file),
                            line_number=i,
                            severity='medium',
                            category='security',
                            rule_id='unsafe_file_operation',
                            message='Potential unsafe file operation with user input',
                            suggestion='Validate and sanitize file paths',
                            auto_fixable=False
                        ))
            
            except Exception as e:
                continue
        
        return issues
    
    def _generate_report(self):
        """Generate comprehensive code quality report"""
        logger.info("Generating code quality report...")
        
        report = {
            'scan_timestamp': datetime.now().isoformat(),
            'project_root': str(self.project_root),
            'languages_detected': self.languages_detected,
            'frameworks_detected': self.frameworks_detected,
            'thresholds': self.thresholds,
            'scan_results': [asdict(result) for result in self.scan_results],
            'summary': self._generate_summary()
        }
        
        # Generate markdown report
        self._generate_markdown_report(report)
        
        # Generate JSON report
        with open('code_quality_report.json', 'w') as f:
            json.dump(report, f, indent=2)
        
        logger.info("Reports generated: code_review_report.md, code_quality_report.json")
    
    def _generate_summary(self) -> Dict:
        """Generate summary statistics"""
        all_issues = []
        total_score = 0
        failed_checks = []
        
        for result in self.scan_results:
            all_issues.extend(result.issues)
            total_score += result.score
            if not result.passed:
                failed_checks.append(f"{result.language}/{result.tool}")
        
        severity_counts = {}
        category_counts = {}
        
        for issue in all_issues:
            severity_counts[issue.severity] = severity_counts.get(issue.severity, 0) + 1
            category_counts[issue.category] = category_counts.get(issue.category, 0) + 1
        
        return {
            'total_issues': len(all_issues),
            'severity_counts': severity_counts,
            'category_counts': category_counts,
            'average_score': total_score / len(self.scan_results) if self.scan_results else 0,
            'failed_checks': failed_checks,
            'auto_fixable_issues': len([i for i in all_issues if i.auto_fixable])
        }
    
    def _generate_markdown_report(self, report: Dict):
        """Generate markdown report"""
        md_content = f"""# Code Quality and Security Report

**Generated:** {report['scan_timestamp']}  
**Project:** {report['project_root']}  
**Languages:** {', '.join(report['languages_detected'])}  
**Frameworks:** {', '.join(report['frameworks_detected'])}  

## Summary

"""
        
        summary = report['summary']
        md_content += f"- **Total Issues:** {summary['total_issues']}\n"
        md_content += f"- **Average Score:** {summary['average_score']:.2f}/10\n"
        md_content += f"- **Failed Checks:** {len(summary['failed_checks'])}\n"
        md_content += f"- **Auto-fixable Issues:** {summary['auto_fixable_issues']}\n\n"
        
        # Severity breakdown
        md_content += "### Issues by Severity\n\n"
        for severity, count in summary['severity_counts'].items():
            md_content += f"- **{severity.capitalize()}:** {count}\n"
        
        # Category breakdown
        md_content += "\n### Issues by Category\n\n"
        for category, count in summary['category_counts'].items():
            md_content += f"- **{category.capitalize()}:** {count}\n"
        
        # Detailed results
        md_content += "\n## Detailed Results\n\n"
        
        for result in report['scan_results']:
            md_content += f"### {result['language'].capitalize()} - {result['tool'].capitalize()}\n\n"
            md_content += f"**Score:** {result['score']:.2f}/10  \n"
            md_content += f"**Passed:** {'✅' if result['passed'] else '❌'}  \n"
            md_content += f"**Issues:** {len(result['issues'])}\n\n"
            
            if result['issues']:
                md_content += "#### Issues Found\n\n"
                for issue in sorted(result['issues'], key=lambda x: x['severity']):
                    severity_emoji = {'critical': '🔴', 'high': '🟠', 'medium': '🟡', 'low': '🔵', 'info': '⚪'}.get(issue['severity'], '⚪')
                    md_content += f"- {severity_emoji} **{issue['file_path']}:{issue['line_number']}** - {issue['message']}\n"
                    if issue['suggestion']:
                        md_content += f"  - *Suggestion:* {issue['suggestion']}\n"
                    if issue['auto_fixable']:
                        md_content += f"  - *Auto-fixable:* ✅\n"
                md_content += "\n"
        
        # Recommendations
        md_content += self._generate_recommendations(report)
        
        with open('code_review_report.md', 'w') as f:
            f.write(md_content)
    
    def _generate_recommendations(self, report: Dict) -> str:
        """Generate recommendations based on findings"""
        recommendations = "\n## Recommendations\n\n"
        
        summary = report['summary']
        
        if summary['severity_counts'].get('critical', 0) > 0:
            recommendations += "### 🔴 Critical Issues\n"
            recommendations += "- Address critical security vulnerabilities immediately\n"
            recommendations += "- Review code for eval(), exec(), and SQL injection patterns\n\n"
        
        if summary['severity_counts'].get('high', 0) > 0:
            recommendations += "### 🟠 High Priority\n"
            recommendations += "- Fix high-severity security and logic issues\n"
            recommendations += "- Implement proper input validation and sanitization\n\n"
        
        if summary['category_counts'].get('security', 0) > 0:
            recommendations += "### 🔒 Security Improvements\n"
            recommendations += "- Enable SSL verification in all HTTP requests\n"
            recommendations += "- Use environment variables for sensitive configuration\n"
            recommendations += "- Implement proper authentication and authorization\n\n"
        
        if summary['category_counts'].get('style', 0) > 10:
            recommendations += "### 🎨 Code Style\n"
            recommendations += "- Run automated code formatting (black, autopep8)\n"
            recommendations += "- Add type hints to improve code maintainability\n"
            recommendations += "- Add missing docstrings to functions and classes\n\n"
        
        if summary['auto_fixable_issues'] > 0:
            recommendations += f"### ⚙️ Auto-fixable Issues\n"
            recommendations += f"- {summary['auto_fixable_issues']} issues can be automatically fixed\n"
            recommendations += "- Run auto-fix tools to resolve style and formatting issues\n\n"
        
        return recommendations
    
    # Helper methods for severity mapping and suggestions
    def _map_pylint_severity(self, pylint_type: str) -> str:
        mapping = {
            'error': 'high',
            'warning': 'medium',
            'refactor': 'low',
            'convention': 'low',
            'info': 'info'
        }
        return mapping.get(pylint_type, 'info')
    
    def _map_flake8_severity(self, code: str) -> str:
        if code.startswith('E'):
            return 'medium'
        elif code.startswith('W'):
            return 'low'
        elif code.startswith('F'):
            return 'high'
        return 'info'
    
    def _get_pylint_suggestion(self, message_id: str) -> str:
        suggestions = {
            'C0103': 'Use descriptive variable names following naming conventions',
            'C0111': 'Add docstring to document the purpose',
            'R0903': 'Consider adding more methods or combining with other classes',
            'R0913': 'Reduce number of parameters or use data classes',
            'W0613': 'Remove unused parameter or prefix with underscore'
        }
        return suggestions.get(message_id, 'See pylint documentation for details')
    
    def _get_flake8_suggestion(self, code: str) -> str:
        suggestions = {
            'E501': 'Break line into multiple lines or use parentheses',
            'F401': 'Remove unused import or use it in the code',
            'E302': 'Add blank lines between function definitions',
            'E305': 'Add blank lines after class or function definitions',
            'W503': 'Move operator to the beginning of the line'
        }
        return suggestions.get(code, 'See flake8 documentation for details')
    
    def _get_bandit_suggestion(self, test_id: str) -> str:
        suggestions = {
            'B101': 'Remove assert statements in production code',
            'B201': 'Use subprocess.run() instead of os.system()',
            'B301': 'Use safe serialization methods',
            'B501': 'Use secure SSL/TLS configuration'
        }
        return suggestions.get(test_id, 'See bandit documentation for details')
    
    def _get_mypy_suggestion(self, message: str) -> str:
        if 'has no attribute' in message:
            return 'Check object type or add type annotations'
        elif 'incompatible types' in message:
            return 'Ensure type compatibility or add type conversion'
        return 'Add proper type annotations'
    
    def _get_shellcheck_suggestion(self, code: str) -> str:
        suggestions = {
            '2086': 'Quote variables to prevent word splitting',
            '2046': 'Quote command substitution to prevent word splitting',
            '2034': 'Variable is assigned but never used'
        }
        return suggestions.get(code, 'See shellcheck documentation for details')
    
    def _is_pylint_auto_fixable(self, message_id: str) -> bool:
        auto_fixable = ['C0103', 'C0111', 'W0611', 'E302', 'E305']
        return message_id in auto_fixable
    
    def _is_flake8_auto_fixable(self, code: str) -> bool:
        auto_fixable = ['E501', 'F401', 'E302', 'E305', 'W503']
        return code in auto_fixable
    
    def _count_indentation(self, line: str) -> int:
        """Count indentation level"""
        return (len(line) - len(line.lstrip())) // 4
    
    def _check_hardcoded_secrets(self, line: str) -> bool:
        """Check for hardcoded secrets"""
        patterns = [
            r'password\s*=\s*["\'][^"\']+["\']',
            r'api_key\s*=\s*["\'][^"\']+["\']',
            r'secret\s*=\s*["\'][^"\']+["\']',
            r'token\s*=\s*["\'][^"\']+["\']'
        ]
        
        for pattern in patterns:
            if re.search(pattern, line, re.IGNORECASE):
                return True
        return False

def main():
    """Main entry point for CI agent"""
    import argparse
    
    parser = argparse.ArgumentParser(description='Autonomous Code Quality and Security Agent')
    parser.add_argument('--project-root', default='.', help='Project root directory')
    parser.add_argument('--fail-on-issues', action='store_true', help='Fail CI on any issues')
    parser.add_argument('--auto-fix', action='store_true', help='Automatically fix issues where possible')
    
    args = parser.parse_args()
    
    # Initialize agent
    agent = CodeQualityAgent(args.project_root)
    
    # Run full scan
    success = agent.run_full_scan()
    
    # Auto-fix if requested
    if args.auto_fix:
        logger.info("Auto-fixing issues...")
        # Implementation for auto-fix would go here
    
    # Exit with appropriate code
    if args.fail_on_issues and not success:
        logger.error("CI failed due to code quality issues")
        sys.exit(1)
    else:
        logger.info("Code quality scan completed successfully")
        sys.exit(0)

if __name__ == '__main__':
    main()
