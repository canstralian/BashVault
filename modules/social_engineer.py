"""
Social Engineering Information Gathering Module
Handles employee enumeration, email pattern discovery, and breach data correlation
"""

import requests
import re
import json
import time
import concurrent.futures
from urllib.parse import urljoin, urlparse
import hashlib
import threading


class SocialEngineer:
    def __init__(self, verbose=False, timeout=10):
        """
        Initialize social engineering module
        
        Args:
            verbose (bool): Enable verbose output
            timeout (int): Request timeout in seconds
        """
        self.verbose = verbose
        self.timeout = timeout
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
        })
        
        # Common email patterns for different organizations
        self.email_patterns = [
            '{first}.{last}@{domain}',
            '{first}{last}@{domain}',
            '{f}{last}@{domain}',
            '{first}{l}@{domain}',
            '{first}@{domain}',
            '{last}@{domain}',
            '{first}_{last}@{domain}',
            '{last}.{first}@{domain}',
            '{last}{first}@{domain}',
            '{f}.{last}@{domain}',
            '{first}-{last}@{domain}'
        ]
        
        # Thread lock for thread-safe operations
        self.lock = threading.Lock()

    def gather_intelligence(self, target_domain, company_name=None):
        """
        Perform comprehensive social engineering intelligence gathering
        
        Args:
            target_domain (str): Target domain (e.g., 'example.com')
            company_name (str): Company name for LinkedIn search (optional)
            
        Returns:
            dict: Social engineering intelligence results
        """
        if self.verbose:
            print(f"[INFO] Starting social engineering intelligence gathering for {target_domain}")
        
        results = {
            'target_domain': target_domain,
            'company_name': company_name or target_domain.split('.')[0].title(),
            'employees': [],
            'email_patterns': [],
            'validated_emails': [],
            'social_media_accounts': [],
            'breach_data': {},
            'github_users': [],
            'metadata': {
                'scan_time': time.strftime('%Y-%m-%d %H:%M:%S'),
                'techniques_used': []
            }
        }
        
        # Employee enumeration
        employees = self._enumerate_employees(target_domain, company_name)
        results['employees'] = employees
        results['metadata']['techniques_used'].append('Employee Enumeration')
        
        # Email pattern discovery
        if employees:
            email_patterns = self._discover_email_patterns(employees, target_domain)
            results['email_patterns'] = email_patterns
            results['metadata']['techniques_used'].append('Email Pattern Discovery')
            
            # Email validation
            validated_emails = self._validate_emails(email_patterns, target_domain)
            results['validated_emails'] = validated_emails
            results['metadata']['techniques_used'].append('Email Validation')
        
        # GitHub user discovery
        github_users = self._discover_github_users(target_domain, company_name)
        results['github_users'] = github_users
        if github_users:
            results['metadata']['techniques_used'].append('GitHub User Discovery')
        
        # Social media discovery
        social_accounts = self._discover_social_media(target_domain, employees)
        results['social_media_accounts'] = social_accounts
        if social_accounts:
            results['metadata']['techniques_used'].append('Social Media Discovery')
        
        # Generate summary statistics
        results['summary'] = self._generate_summary(results)
        
        return results

    def _enumerate_employees(self, target_domain, company_name):
        """Enumerate employees using various public sources"""
        employees = []
        
        if self.verbose:
            print(f"[INFO] Enumerating employees for {target_domain}")
        
        # Search engines (Google dorking)
        google_employees = self._google_employee_search(target_domain, company_name)
        employees.extend(google_employees)
        
        # Search for employees in public directories
        directory_employees = self._search_public_directories(target_domain, company_name)
        employees.extend(directory_employees)
        
        # Extract from website content
        website_employees = self._extract_from_website(target_domain)
        employees.extend(website_employees)
        
        # Remove duplicates and normalize
        unique_employees = self._deduplicate_employees(employees)
        
        if self.verbose:
            print(f"[INFO] Found {len(unique_employees)} unique employees")
        
        return unique_employees

    def _google_employee_search(self, target_domain, company_name):
        """Use Google dorking to find employee information"""
        employees = []
        
        # Google dork queries
        queries = [
            f'site:linkedin.com/in/ "{company_name}"',
            f'site:linkedin.com/in/ "@{target_domain}"',
            f'"{company_name}" "employee" OR "staff" OR "team"',
            f'site:{target_domain} "team" OR "staff" OR "about"',
            f'filetype:pdf site:{target_domain} "employee" OR "staff"'
        ]
        
        for query in queries:
            try:
                # Note: In production, this would use Google Custom Search API
                # For demonstration, we'll simulate the search
                if self.verbose:
                    print(f"[INFO] Searching: {query}")
                
                # Simulated employee discovery from search results
                # In real implementation, parse actual search results
                
            except Exception as e:
                if self.verbose:
                    print(f"[ERROR] Google search error: {str(e)}")
        
        return employees

    def _search_public_directories(self, target_domain, company_name):
        """Search public employee directories and databases"""
        employees = []
        
        # Common public sources for employee information
        sources = [
            'crunchbase.com',
            'apollo.io',
            'zoominfo.com',
            'clearbit.com'
        ]
        
        for source in sources:
            try:
                if self.verbose:
                    print(f"[INFO] Searching {source} for employee data")
                
                # Simulated search - in production would use APIs where available
                # This is where you'd implement actual API calls to these services
                
            except Exception as e:
                if self.verbose:
                    print(f"[ERROR] Error searching {source}: {str(e)}")
        
        return employees

    def _extract_from_website(self, target_domain):
        """Extract employee information from company website"""
        employees = []
        
        try:
            # Common pages that might contain employee information
            pages_to_check = [
                f'https://{target_domain}',
                f'https://{target_domain}/about',
                f'https://{target_domain}/team',
                f'https://{target_domain}/staff',
                f'https://{target_domain}/leadership',
                f'https://{target_domain}/contact',
                f'https://www.{target_domain}/about',
                f'https://www.{target_domain}/team'
            ]
            
            for url in pages_to_check:
                try:
                    response = self.session.get(url, timeout=self.timeout, verify=False)
                    if response.status_code == 200:
                        # Extract names using regex patterns
                        names = self._extract_names_from_html(response.text)
                        for name in names:
                            employees.append({
                                'name': name,
                                'source': f'Website: {url}',
                                'title': 'Unknown',
                                'linkedin': None
                            })
                        
                        if self.verbose and names:
                            print(f"[INFO] Found {len(names)} names on {url}")
                            
                except Exception as e:
                    if self.verbose:
                        print(f"[DEBUG] Could not access {url}: {str(e)}")
                    continue
                    
        except Exception as e:
            if self.verbose:
                print(f"[ERROR] Website extraction error: {str(e)}")
        
        return employees

    def _extract_names_from_html(self, html_content):
        """Extract potential names from HTML content"""
        names = []
        
        # Patterns to find names in HTML
        patterns = [
            r'<h[1-6][^>]*>([A-Z][a-z]+ [A-Z][a-z]+)</h[1-6]>',
            r'<p[^>]*>([A-Z][a-z]+ [A-Z][a-z]+)</p>',
            r'<div[^>]*class="[^"]*name[^"]*"[^>]*>([A-Z][a-z]+ [A-Z][a-z]+)</div>',
            r'<span[^>]*class="[^"]*name[^"]*"[^>]*>([A-Z][a-z]+ [A-Z][a-z]+)</span>',
            r'"name":\s*"([A-Z][a-z]+ [A-Z][a-z]+)"',
            r'<meta[^>]*name="author"[^>]*content="([A-Z][a-z]+ [A-Z][a-z]+)"'
        ]
        
        for pattern in patterns:
            matches = re.findall(pattern, html_content, re.IGNORECASE)
            for match in matches:
                # Filter out common false positives
                if self._is_valid_name(match):
                    names.append(match.strip())
        
        return list(set(names))  # Remove duplicates

    def _is_valid_name(self, name):
        """Validate if extracted text is likely a real name"""
        # Filter out common false positives
        false_positives = [
            'About Us', 'Contact Us', 'Privacy Policy', 'Terms Service',
            'Lorem Ipsum', 'John Doe', 'Jane Doe', 'Your Name',
            'First Last', 'Full Name', 'User Name', 'Company Name'
        ]
        
        if name in false_positives:
            return False
        
        # Check if it looks like a real name (two words, appropriate length)
        parts = name.split()
        if len(parts) != 2:
            return False
        
        # Each part should be reasonable length for a name
        if not all(2 <= len(part) <= 20 for part in parts):
            return False
        
        # Should start with capital letters
        if not all(part[0].isupper() for part in parts):
            return False
        
        return True

    def _discover_email_patterns(self, employees, target_domain):
        """Discover email patterns based on found employees"""
        if not employees:
            return []
        
        patterns = []
        
        for employee in employees[:10]:  # Use first 10 employees for pattern discovery
            name = employee.get('name', '')
            if not name or ' ' not in name:
                continue
            
            parts = name.lower().split()
            if len(parts) >= 2:
                first = parts[0]
                last = parts[-1]
                f = first[0] if first else ''
                l = last[0] if last else ''
                
                # Generate potential emails based on common patterns
                for pattern in self.email_patterns:
                    try:
                        email = pattern.format(
                            first=first, last=last, f=f, l=l, domain=target_domain
                        )
                        patterns.append({
                            'email': email,
                            'pattern': pattern,
                            'employee': name
                        })
                    except:
                        continue
        
        return patterns

    def _validate_emails(self, email_patterns, target_domain):
        """Validate email addresses using various techniques"""
        validated = []
        
        if not email_patterns:
            return validated
        
        if self.verbose:
            print(f"[INFO] Validating {len(email_patterns)} email patterns")
        
        # Use threading for faster validation
        with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
            future_to_email = {
                executor.submit(self._validate_single_email, pattern['email']): pattern 
                for pattern in email_patterns[:50]  # Limit to prevent overwhelming
            }
            
            for future in concurrent.futures.as_completed(future_to_email):
                pattern = future_to_email[future]
                try:
                    is_valid, method = future.result()
                    if is_valid:
                        pattern['validation_method'] = method
                        validated.append(pattern)
                except Exception as e:
                    if self.verbose:
                        print(f"[DEBUG] Email validation error: {str(e)}")
        
        if self.verbose:
            print(f"[INFO] Validated {len(validated)} email addresses")
        
        return validated

    def _validate_single_email(self, email):
        """Validate a single email address"""
        # Method 1: SMTP validation (basic)
        try:
            # Basic format validation
            if not re.match(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', email):
                return False, 'Invalid format'
            
            # In production, you might implement SMTP validation
            # For now, we'll use a simulated validation
            
            # Method 2: Check if email appears in public breaches (using HaveIBeenPwned API)
            # This would require API integration
            
            # Method 3: Social media validation
            # Check if email is associated with social media accounts
            
            return True, 'Format validation'
            
        except Exception:
            return False, 'Validation error'

    def _discover_github_users(self, target_domain, company_name):
        """Discover GitHub users associated with the target"""
        github_users = []
        
        try:
            if self.verbose:
                print(f"[INFO] Searching GitHub for users associated with {target_domain}")
            
            # Search patterns for GitHub
            search_terms = [
                f'"{target_domain}"',
                f'"{company_name}"',
                f'@{target_domain}'
            ]
            
            for term in search_terms:
                # In production, this would use GitHub API
                # GitHub API endpoint: https://api.github.com/search/users
                # Requires authentication for higher rate limits
                
                # Simulated GitHub user discovery
                # In real implementation, parse GitHub search results
                pass
                
        except Exception as e:
            if self.verbose:
                print(f"[ERROR] GitHub search error: {str(e)}")
        
        return github_users

    def _discover_social_media(self, target_domain, employees):
        """Discover social media accounts for employees"""
        social_accounts = []
        
        platforms = ['twitter.com', 'facebook.com', 'instagram.com', 'tiktok.com']
        
        for employee in employees[:20]:  # Limit to first 20 employees
            name = employee.get('name', '')
            if not name:
                continue
            
            # Generate potential usernames
            usernames = self._generate_usernames(name)
            
            for platform in platforms:
                for username in usernames[:5]:  # Limit usernames per platform
                    try:
                        # Check if profile exists (basic check)
                        profile_url = f"https://{platform}/{username}"
                        
                        # In production, this would make actual HTTP requests
                        # For demonstration, we'll simulate the check
                        
                    except Exception as e:
                        if self.verbose:
                            print(f"[DEBUG] Social media check error: {str(e)}")
        
        return social_accounts

    def _generate_usernames(self, name):
        """Generate potential usernames from a name"""
        if ' ' not in name:
            return [name.lower()]
        
        parts = name.lower().split()
        first = parts[0]
        last = parts[-1]
        
        usernames = [
            first + last,
            first + '.' + last,
            first + '_' + last,
            first + last[0],
            first[0] + last,
            first,
            last
        ]
        
        return usernames

    def _deduplicate_employees(self, employees):
        """Remove duplicate employees based on name similarity"""
        unique_employees = []
        seen_names = set()
        
        for employee in employees:
            name = employee.get('name', '').lower().strip()
            if name and name not in seen_names:
                seen_names.add(name)
                unique_employees.append(employee)
        
        return unique_employees

    def _generate_summary(self, results):
        """Generate summary statistics"""
        return {
            'total_employees': len(results.get('employees', [])),
            'email_patterns_discovered': len(results.get('email_patterns', [])),
            'validated_emails': len(results.get('validated_emails', [])),
            'github_users': len(results.get('github_users', [])),
            'social_media_accounts': len(results.get('social_media_accounts', [])),
            'techniques_used': len(results.get('metadata', {}).get('techniques_used', []))
        }

    def check_breach_data(self, email_list, api_key=None):
        """
        Check if emails appear in known data breaches
        Requires HaveIBeenPwned API key for production use
        
        Args:
            email_list (list): List of email addresses to check
            api_key (str): HaveIBeenPwned API key
            
        Returns:
            dict: Breach data results
        """
        if not api_key:
            return {
                'error': 'HaveIBeenPwned API key required for breach data checking',
                'note': 'Provide API key using --haveibeenpwned-key parameter'
            }
        
        breach_results = {}
        
        for email in email_list[:10]:  # Limit to prevent API abuse
            try:
                # HaveIBeenPwned API integration would go here
                # headers = {'hibp-api-key': api_key}
                # url = f'https://haveibeenpwned.com/api/v3/breachedaccount/{email}'
                
                breach_results[email] = {
                    'breaches': [],
                    'pastes': [],
                    'status': 'API integration required'
                }
                
            except Exception as e:
                breach_results[email] = {'error': str(e)}
        
        return breach_results