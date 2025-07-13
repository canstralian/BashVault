
#!/usr/bin/env python3
"""
Auto-fix capabilities for common code quality issues
"""

import os
import re
import ast
import subprocess
from pathlib import Path
from typing import List, Dict, Optional
import logging

logger = logging.getLogger(__name__)

class AutoFixer:
    """Automatically fix common code quality issues"""
    
    def __init__(self, project_root: str = "."):
        self.project_root = Path(project_root)
        self.fixes_applied = []
    
    def apply_all_fixes(self) -> List[str]:
        """Apply all available auto-fixes"""
        logger.info("Applying auto-fixes...")
        
        # Python fixes
        self._fix_python_imports()
        self._fix_python_formatting()
        self._fix_python_style()
        self._fix_security_issues()
        
        # Shell script fixes
        self._fix_shell_scripts()
        
        return self.fixes_applied
    
    def _fix_python_imports(self):
        """Fix Python import issues"""
        logger.info("Fixing Python imports...")
        
        try:
            # Use isort to fix import order
            cmd = ["python", "-m", "isort", "--profile", "black", "."]
            result = subprocess.run(cmd, capture_output=True, text=True, cwd=self.project_root)
            
            if result.returncode == 0:
                self.fixes_applied.append("Fixed import ordering with isort")
            
            # Remove unused imports
            for py_file in self.project_root.glob("**/*.py"):
                if py_file.name.startswith('.'):
                    continue
                    
                self._remove_unused_imports(py_file)
                
        except Exception as e:
            logger.error(f"Error fixing imports: {str(e)}")
    
    def _fix_python_formatting(self):
        """Fix Python code formatting"""
        logger.info("Fixing Python formatting...")
        
        try:
            # Use black for code formatting
            cmd = ["python", "-m", "black", "--line-length", "88", "."]
            result = subprocess.run(cmd, capture_output=True, text=True, cwd=self.project_root)
            
            if result.returncode == 0:
                self.fixes_applied.append("Applied black code formatting")
            
            # Use autopep8 for PEP 8 compliance
            cmd = ["python", "-m", "autopep8", "--in-place", "--recursive", "."]
            result = subprocess.run(cmd, capture_output=True, text=True, cwd=self.project_root)
            
            if result.returncode == 0:
                self.fixes_applied.append("Applied autopep8 formatting")
                
        except Exception as e:
            logger.error(f"Error fixing formatting: {str(e)}")
    
    def _fix_python_style(self):
        """Fix Python style issues"""
        logger.info("Fixing Python style issues...")
        
        for py_file in self.project_root.glob("**/*.py"):
            if py_file.name.startswith('.'):
                continue
                
            try:
                with open(py_file, 'r', encoding='utf-8') as f:
                    content = f.read()
                
                original_content = content
                
                # Fix common style issues
                content = self._fix_docstrings(content)
                content = self._fix_variable_names(content)
                content = self._fix_line_endings(content)
                content = self._fix_trailing_whitespace(content)
                
                if content != original_content:
                    with open(py_file, 'w', encoding='utf-8') as f:
                        f.write(content)
                    self.fixes_applied.append(f"Fixed style issues in {py_file}")
                    
            except Exception as e:
                logger.error(f"Error fixing style in {py_file}: {str(e)}")
    
    def _fix_security_issues(self):
        """Fix security issues automatically"""
        logger.info("Fixing security issues...")
        
        for py_file in self.project_root.glob("**/*.py"):
            if py_file.name.startswith('.'):
                continue
                
            try:
                with open(py_file, 'r', encoding='utf-8') as f:
                    content = f.read()
                
                original_content = content
                
                # Fix debug mode in production
                content = re.sub(
                    r'app\.run\([^)]*debug=True',
                    'app.run(debug=False',
                    content
                )
                
                # Fix SSL verification
                content = re.sub(
                    r'verify=False',
                    'verify=True',
                    content
                )
                
                # Fix SQL injection patterns (basic)
                content = re.sub(
                    r'cursor\.execute\s*\(\s*["\']([^"\']*%[^"\']*)["\']',
                    r'cursor.execute("\1", ',
                    content
                )
                
                if content != original_content:
                    with open(py_file, 'w', encoding='utf-8') as f:
                        f.write(content)
                    self.fixes_applied.append(f"Fixed security issues in {py_file}")
                    
            except Exception as e:
                logger.error(f"Error fixing security in {py_file}: {str(e)}")
    
    def _fix_shell_scripts(self):
        """Fix shell script issues"""
        logger.info("Fixing shell script issues...")
        
        for shell_file in self.project_root.glob("**/*.sh"):
            try:
                with open(shell_file, 'r', encoding='utf-8') as f:
                    content = f.read()
                
                original_content = content
                
                # Add quotes around variables
                content = re.sub(r'\$([A-Za-z_][A-Za-z0-9_]*)', r'"$\1"', content)
                
                # Fix shebang
                if not content.startswith('#!'):
                    content = '#!/bin/bash\n' + content
                
                if content != original_content:
                    with open(shell_file, 'w', encoding='utf-8') as f:
                        f.write(content)
                    self.fixes_applied.append(f"Fixed shell script issues in {shell_file}")
                    
            except Exception as e:
                logger.error(f"Error fixing shell script {shell_file}: {str(e)}")
    
    def _remove_unused_imports(self, py_file: Path):
        """Remove unused imports from Python file"""
        try:
            with open(py_file, 'r', encoding='utf-8') as f:
                content = f.read()
            
            # Parse AST to find imports
            try:
                tree = ast.parse(content)
                imports = []
                used_names = set()
                
                # Find all imports
                for node in ast.walk(tree):
                    if isinstance(node, ast.Import):
                        for alias in node.names:
                            imports.append(alias.name)
                    elif isinstance(node, ast.ImportFrom):
                        for alias in node.names:
                            imports.append(alias.name)
                    elif isinstance(node, ast.Name):
                        used_names.add(node.id)
                
                # Remove unused imports (basic implementation)
                lines = content.split('\n')
                new_lines = []
                
                for line in lines:
                    if line.strip().startswith('import ') or line.strip().startswith('from '):
                        # Check if import is used
                        import_match = re.search(r'(?:import|from)\s+([A-Za-z_][A-Za-z0-9_]*)', line)
                        if import_match:
                            import_name = import_match.group(1)
                            if import_name in used_names or import_name in ['os', 'sys', 'json']:
                                new_lines.append(line)
                            # Skip unused imports
                        else:
                            new_lines.append(line)
                    else:
                        new_lines.append(line)
                
                new_content = '\n'.join(new_lines)
                
                if new_content != content:
                    with open(py_file, 'w', encoding='utf-8') as f:
                        f.write(new_content)
                    self.fixes_applied.append(f"Removed unused imports from {py_file}")
                    
            except SyntaxError:
                # Skip files with syntax errors
                pass
                
        except Exception as e:
            logger.error(f"Error removing unused imports from {py_file}: {str(e)}")
    
    def _fix_docstrings(self, content: str) -> str:
        """Add basic docstrings to functions"""
        lines = content.split('\n')
        new_lines = []
        
        for i, line in enumerate(lines):
            new_lines.append(line)
            
            # Check if this is a function definition
            if line.strip().startswith('def '):
                # Check if next line is a docstring
                if i + 1 < len(lines):
                    next_line = lines[i + 1].strip()
                    if not next_line.startswith('"""') and not next_line.startswith("'''"):
                        # Add basic docstring
                        indent = len(line) - len(line.lstrip())
                        func_name = re.search(r'def\s+([A-Za-z_][A-Za-z0-9_]*)', line)
                        if func_name:
                            docstring = f'{" " * (indent + 4)}"""TODO: Add docstring for {func_name.group(1)}"""'
                            new_lines.append(docstring)
        
        return '\n'.join(new_lines)
    
    def _fix_variable_names(self, content: str) -> str:
        """Fix variable naming conventions"""
        # Convert camelCase to snake_case (basic implementation)
        content = re.sub(r'([a-z])([A-Z])', r'\1_\2', content)
        return content.lower()
    
    def _fix_line_endings(self, content: str) -> str:
        """Fix line endings"""
        return content.replace('\r\n', '\n').replace('\r', '\n')
    
    def _fix_trailing_whitespace(self, content: str) -> str:
        """Remove trailing whitespace"""
        lines = content.split('\n')
        return '\n'.join(line.rstrip() for line in lines)

def main():
    """Main entry point for auto-fixer"""
    import argparse
    
    parser = argparse.ArgumentParser(description='Auto-fix code quality issues')
    parser.add_argument('--project-root', default='.', help='Project root directory')
    parser.add_argument('--dry-run', action='store_true', help='Show what would be fixed without applying')
    
    args = parser.parse_args()
    
    fixer = AutoFixer(args.project_root)
    
    if args.dry_run:
        logger.info("Dry run mode - no changes will be made")
        # In dry run, we would analyze but not apply fixes
        return
    
    fixes = fixer.apply_all_fixes()
    
    if fixes:
        logger.info(f"Applied {len(fixes)} fixes:")
        for fix in fixes:
            logger.info(f"  - {fix}")
    else:
        logger.info("No fixes were needed")

if __name__ == '__main__':
    main()
