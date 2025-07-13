
#!/usr/bin/env python3
"""
CI Integration for Code Quality Agent
Provides integration with various CI/CD systems
"""

import os
import json
import subprocess
import sys
from pathlib import Path
from typing import Dict, List, Optional
import logging

logger = logging.getLogger(__name__)

class CIIntegration:
    """CI/CD integration for code quality agent"""
    
    def __init__(self, ci_system: str = "github"):
        self.ci_system = ci_system
        self.project_root = Path(".")
        
    def setup_pre_commit_hook(self):
        """Setup pre-commit hook for code quality checks"""
        hook_content = """#!/bin/bash
# Pre-commit hook for code quality
echo "Running code quality checks..."

python ci_agent.py --project-root . --fail-on-issues

if [ $? -ne 0 ]; then
    echo "❌ Code quality checks failed. Please fix issues before committing."
    exit 1
fi

echo "✅ Code quality checks passed!"
"""
        
        git_hooks_dir = Path(".git/hooks")
        if git_hooks_dir.exists():
            hook_file = git_hooks_dir / "pre-commit"
            with open(hook_file, 'w') as f:
                f.write(hook_content)
            hook_file.chmod(0o755)
            logger.info("Pre-commit hook installed")
        else:
            logger.warning("Git hooks directory not found")
    
    def setup_github_action(self):
        """Setup GitHub Action for code quality"""
        action_content = """name: Code Quality and Security Scan

on:
  push:
    branches: [ main, develop ]
  pull_request:
    branches: [ main, develop ]

jobs:
  code-quality:
    runs-on: ubuntu-latest
    
    steps:
    - uses: actions/checkout@v3
    
    - name: Set up Python
      uses: actions/setup-python@v4
      with:
        python-version: '3.9'
    
    - name: Install dependencies
      run: |
        python -m pip install --upgrade pip
        pip install -r requirements.txt
        pip install pylint flake8 bandit mypy
    
    - name: Install shellcheck
      run: |
        sudo apt-get update
        sudo apt-get install shellcheck
    
    - name: Run Code Quality Scan
      run: |
        python ci_agent.py --project-root . --fail-on-issues
    
    - name: Upload Code Quality Report
      uses: actions/upload-artifact@v3
      if: always()
      with:
        name: code-quality-report
        path: |
          code_review_report.md
          code_quality_report.json
    
    - name: Comment PR with Results
      if: github.event_name == 'pull_request' && always()
      uses: actions/github-script@v6
      with:
        script: |
          const fs = require('fs');
          if (fs.existsSync('code_review_report.md')) {
            const report = fs.readFileSync('code_review_report.md', 'utf8');
            github.rest.issues.createComment({
              issue_number: context.issue.number,
              owner: context.repo.owner,
              repo: context.repo.repo,
              body: `## Code Quality Report\\n\\n${report}`
            });
          }
"""
        
        workflows_dir = Path(".github/workflows")
        workflows_dir.mkdir(parents=True, exist_ok=True)
        
        with open(workflows_dir / "code-quality.yml", 'w') as f:
            f.write(action_content)
        
        logger.info("GitHub Action workflow created")
    
    def setup_replit_ci(self):
        """Setup Replit-specific CI integration"""
        replit_config = {
            "scripts": {
                "quality_check": "python ci_agent.py --project-root .",
                "quality_fix": "python ci_agent.py --project-root . --auto-fix",
                "quality_report": "python ci_agent.py --project-root . && cat code_review_report.md"
            },
            "workflows": {
                "pre_deploy": [
                    "python ci_agent.py --project-root . --fail-on-issues"
                ]
            }
        }
        
        with open('.replit_ci.json', 'w') as f:
            json.dump(replit_config, f, indent=2)
        
        logger.info("Replit CI configuration created")
    
    def create_quality_dashboard(self):
        """Create a simple quality dashboard"""
        dashboard_content = """<!DOCTYPE html>
<html>
<head>
    <title>Code Quality Dashboard</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; }
        .metric { display: inline-block; margin: 10px; padding: 20px; border: 1px solid #ddd; border-radius: 5px; }
        .critical { background-color: #ffebee; }
        .high { background-color: #fff3e0; }
        .medium { background-color: #f3e5f5; }
        .low { background-color: #e8f5e8; }
        .passed { color: green; }
        .failed { color: red; }
    </style>
</head>
<body>
    <h1>Code Quality Dashboard</h1>
    <div id="metrics"></div>
    <div id="report"></div>
    
    <script>
        // Load quality report
        fetch('code_quality_report.json')
            .then(response => response.json())
            .then(data => {
                displayMetrics(data);
                displayReport(data);
            });
        
        function displayMetrics(data) {
            const metrics = document.getElementById('metrics');
            const summary = data.summary;
            
            metrics.innerHTML = `
                <div class="metric">
                    <h3>Total Issues</h3>
                    <p>${summary.total_issues}</p>
                </div>
                <div class="metric">
                    <h3>Average Score</h3>
                    <p>${summary.average_score.toFixed(1)}/10</p>
                </div>
                <div class="metric critical">
                    <h3>Critical</h3>
                    <p>${summary.severity_counts.critical || 0}</p>
                </div>
                <div class="metric high">
                    <h3>High</h3>
                    <p>${summary.severity_counts.high || 0}</p>
                </div>
                <div class="metric medium">
                    <h3>Medium</h3>
                    <p>${summary.severity_counts.medium || 0}</p>
                </div>
                <div class="metric low">
                    <h3>Low</h3>
                    <p>${summary.severity_counts.low || 0}</p>
                </div>
            `;
        }
        
        function displayReport(data) {
            const report = document.getElementById('report');
            let html = '<h2>Scan Results</h2>';
            
            data.scan_results.forEach(result => {
                const status = result.passed ? 'passed' : 'failed';
                html += `
                    <div class="metric">
                        <h3>${result.language} - ${result.tool}</h3>
                        <p>Score: ${result.score.toFixed(1)}/10</p>
                        <p class="${status}">${result.passed ? 'PASSED' : 'FAILED'}</p>
                        <p>Issues: ${result.issues.length}</p>
                    </div>
                `;
            });
            
            report.innerHTML = html;
        }
    </script>
</body>
</html>"""
        
        with open('quality_dashboard.html', 'w') as f:
            f.write(dashboard_content)
        
        logger.info("Quality dashboard created")

def main():
    """Main entry point for CI integration setup"""
    import argparse
    
    parser = argparse.ArgumentParser(description='CI Integration Setup')
    parser.add_argument('--setup-hooks', action='store_true', help='Setup pre-commit hooks')
    parser.add_argument('--setup-github', action='store_true', help='Setup GitHub Actions')
    parser.add_argument('--setup-replit', action='store_true', help='Setup Replit CI')
    parser.add_argument('--create-dashboard', action='store_true', help='Create quality dashboard')
    
    args = parser.parse_args()
    
    ci = CIIntegration()
    
    if args.setup_hooks:
        ci.setup_pre_commit_hook()
    
    if args.setup_github:
        ci.setup_github_action()
    
    if args.setup_replit:
        ci.setup_replit_ci()
    
    if args.create_dashboard:
        ci.create_quality_dashboard()
    
    if not any(vars(args).values()):
        # Setup everything by default
        ci.setup_pre_commit_hook()
        ci.setup_github_action()
        ci.setup_replit_ci()
        ci.create_quality_dashboard()
        logger.info("All CI integrations setup complete")

if __name__ == '__main__':
    main()
