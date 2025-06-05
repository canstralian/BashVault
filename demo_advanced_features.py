#!/usr/bin/env python3
"""
Advanced Reconnaissance Features Demo
Demonstrates the new capabilities added to InfoGather v2.0
"""

import json
import time
from modules.social_engineer import SocialEngineer
from modules.advanced_dns import AdvancedDNS
from modules.cloud_discovery import CloudDiscovery

def print_section_header(title):
    """Print formatted section header"""
    print(f"\n{'='*60}")
    print(f" {title}")
    print(f"{'='*60}")

def print_subsection_header(title):
    """Print formatted subsection header"""
    print(f"\n{'-'*40}")
    print(f" {title}")
    print(f"{'-'*40}")

def demo_social_engineering():
    """Demonstrate social engineering intelligence features"""
    print_section_header("SOCIAL ENGINEERING INTELLIGENCE DEMO")
    
    # Initialize the social engineering module
    social_engineer = SocialEngineer(verbose=True)
    
    # Demo domain
    demo_domain = "github.com"
    
    print(f"[DEMO] Gathering social engineering intelligence for: {demo_domain}")
    print("[NOTE] This demonstrates the framework - actual implementation would require API keys")
    
    # Show the structure of what would be gathered
    demo_results = {
        'target_domain': demo_domain,
        'company_name': 'GitHub',
        'employees': [
            {
                'name': 'John Developer',
                'source': 'LinkedIn Search',
                'title': 'Software Engineer',
                'linkedin': 'https://linkedin.com/in/johndeveloper'
            }
        ],
        'email_patterns': [
            {
                'email': 'john.developer@github.com',
                'pattern': '{first}.{last}@{domain}',
                'employee': 'John Developer'
            }
        ],
        'validated_emails': [
            {
                'email': 'john.developer@github.com',
                'validation_method': 'Format validation',
                'pattern': '{first}.{last}@{domain}'
            }
        ],
        'github_users': [
            {
                'username': 'johndeveloper',
                'profile_url': 'https://github.com/johndeveloper',
                'repositories': 15,
                'followers': 42
            }
        ],
        'summary': {
            'total_employees': 1,
            'email_patterns_discovered': 1,
            'validated_emails': 1,
            'github_users': 1,
            'techniques_used': 4
        }
    }
    
    print(f"\n[RESULTS] Social Engineering Intelligence:")
    print(f"├── Employees Found: {demo_results['summary']['total_employees']}")
    print(f"├── Email Patterns: {demo_results['summary']['email_patterns_discovered']}")
    print(f"├── Validated Emails: {demo_results['summary']['validated_emails']}")
    print(f"├── GitHub Users: {demo_results['summary']['github_users']}")
    print(f"└── Techniques Used: {demo_results['summary']['techniques_used']}")
    
    print_subsection_header("Key Features Demonstrated")
    print("✓ Employee enumeration from multiple sources")
    print("✓ Email pattern discovery and validation")
    print("✓ GitHub user discovery")
    print("✓ Social media account correlation")
    print("✓ Breach data checking (with API key)")

def demo_advanced_dns():
    """Demonstrate advanced DNS intelligence features"""
    print_section_header("ADVANCED DNS INTELLIGENCE DEMO")
    
    # Initialize the advanced DNS module
    advanced_dns = AdvancedDNS(verbose=True)
    
    demo_domain = "cloudflare.com"
    
    print(f"[DEMO] Advanced DNS analysis for: {demo_domain}")
    print("[NOTE] Some features require external APIs for full functionality")
    
    # Demonstrate DNS over HTTPS bypass
    print_subsection_header("DNS over HTTPS Bypass")
    print("Testing multiple DoH resolvers to bypass local DNS filtering...")
    
    demo_doh_results = {
        'resolvers_tested': ['cloudflare-dns.com', 'dns.google', 'dns.quad9.net'],
        'successful_queries': [
            {
                'resolver': 'cloudflare-dns.com',
                'results': {
                    'A': {'status': 0, 'answers': [{'data': '104.16.132.229'}]},
                    'AAAA': {'status': 0, 'answers': [{'data': '2606:4700::6810:84e5'}]}
                }
            }
        ],
        'response_analysis': {
            'response_variations': {},
            'potential_filtering': []
        }
    }
    
    print(f"├── DoH Resolvers Tested: {len(demo_doh_results['resolvers_tested'])}")
    print(f"├── Successful Queries: {len(demo_doh_results['successful_queries'])}")
    print(f"└── Filtering Detected: {len(demo_doh_results['response_analysis']['potential_filtering'])}")
    
    # Demonstrate DNS tunneling detection
    print_subsection_header("DNS Tunneling Detection")
    print("Analyzing subdomains for tunneling indicators...")
    
    demo_tunneling = {
        'indicators': [
            {
                'type': 'High Entropy Subdomains',
                'severity': 'Medium',
                'description': 'Multiple subdomains with high entropy detected',
                'count': 3
            }
        ],
        'subdomain_entropy': {
            'high_entropy_count': 3,
            'average_entropy': 2.8,
            'entropy_threshold': 3.5
        }
    }
    
    print(f"├── Tunneling Indicators: {len(demo_tunneling['indicators'])}")
    print(f"├── High Entropy Subdomains: {demo_tunneling['subdomain_entropy']['high_entropy_count']}")
    print(f"└── Average Entropy: {demo_tunneling['subdomain_entropy']['average_entropy']:.2f}")
    
    # Demonstrate Certificate Transparency mining
    print_subsection_header("Certificate Transparency Mining")
    print("Mining CT logs for comprehensive certificate data...")
    
    demo_ct = {
        'certificates': [
            {
                'common_name': '*.cloudflare.com',
                'issuer_name': 'DigiCert Inc',
                'not_before': '2024-01-01T00:00:00Z',
                'not_after': '2024-12-31T23:59:59Z'
            }
        ],
        'subdomain_discovery': [
            'api.cloudflare.com',
            'www.cloudflare.com', 
            'blog.cloudflare.com',
            'dash.cloudflare.com'
        ],
        'certificate_analysis': {
            'total_certificates': 15,
            'issuer_distribution': {'DigiCert Inc': 12, 'Let\'s Encrypt': 3},
            'security_insights': [
                {
                    'type': 'Short-lived Certificate Usage',
                    'description': 'Significant use of short-lived certificates detected',
                    'percentage': 30.0
                }
            ]
        }
    }
    
    print(f"├── Certificates Found: {demo_ct['certificate_analysis']['total_certificates']}")
    print(f"├── Subdomains Discovered: {len(demo_ct['subdomain_discovery'])}")
    print(f"├── Unique Issuers: {len(demo_ct['certificate_analysis']['issuer_distribution'])}")
    print(f"└── Security Insights: {len(demo_ct['certificate_analysis']['security_insights'])}")
    
    print_subsection_header("Key Features Demonstrated")
    print("✓ DNS over HTTPS bypass techniques")
    print("✓ Historical DNS data analysis")
    print("✓ DNS tunneling detection")
    print("✓ Certificate transparency log mining")
    print("✓ Advanced subdomain enumeration")

def demo_cloud_discovery():
    """Demonstrate cloud asset discovery features"""
    print_section_header("CLOUD ASSET DISCOVERY DEMO")
    
    # Initialize the cloud discovery module
    cloud_discovery = CloudDiscovery(verbose=True)
    
    demo_domain = "netflix.com"
    
    print(f"[DEMO] Cloud asset discovery for: {demo_domain}")
    print("[NOTE] Actual cloud discovery requires proper API credentials")
    
    # Demonstrate AWS asset discovery
    print_subsection_header("AWS Asset Discovery")
    print("Discovering AWS S3 buckets and services...")
    
    demo_aws = {
        'buckets': [
            {
                'name': 'netflix-assets',
                'exists': True,
                'accessible': False,
                'region': 'us-east-1'
            },
            {
                'name': 'netflix-public',
                'exists': True,
                'accessible': True,
                'files': [
                    {'key': 'images/logo.png', 'size': 15420},
                    {'key': 'css/styles.css', 'size': 8932}
                ],
                'security_issues': [
                    {
                        'type': 'Public Read Access',
                        'severity': 'High',
                        'description': 'Bucket contents are publicly readable'
                    }
                ]
            }
        ],
        'cloudfront_distributions': [
            {
                'domain': 'netflix.com',
                'cloudfront_domain': 'd1234567890123.cloudfront.net',
                'type': 'CNAME'
            }
        ]
    }
    
    print(f"├── S3 Buckets Found: {len(demo_aws['buckets'])}")
    print(f"├── Accessible Buckets: {len([b for b in demo_aws['buckets'] if b['accessible']])}")
    print(f"└── CloudFront Distributions: {len(demo_aws['cloudfront_distributions'])}")
    
    # Demonstrate Azure asset discovery
    print_subsection_header("Azure Asset Discovery")
    print("Discovering Azure storage accounts and services...")
    
    demo_azure = {
        'storage_accounts': [
            {
                'name': 'netflixstorage',
                'exists': True,
                'accessible_containers': [],
                'blob_endpoints': ['https://netflixstorage.blob.core.windows.net/']
            }
        ],
        'app_services': [
            {
                'name': 'netflix-api',
                'url': 'https://netflix-api.azurewebsites.net',
                'status_code': 200
            }
        ]
    }
    
    print(f"├── Storage Accounts: {len(demo_azure['storage_accounts'])}")
    print(f"├── App Services: {len(demo_azure['app_services'])}")
    print(f"└── Accessible Containers: {len(demo_azure['storage_accounts'][0]['accessible_containers'])}")
    
    # Demonstrate GCP asset discovery
    print_subsection_header("Google Cloud Discovery")
    print("Discovering GCP storage buckets and services...")
    
    demo_gcp = {
        'buckets': [
            {
                'name': 'netflix-data',
                'exists': True,
                'accessible': False
            }
        ],
        'app_engine_services': [
            {
                'service': 'netflix.appspot.com',
                'url': 'https://netflix.appspot.com',
                'status_code': 404
            }
        ]
    }
    
    print(f"├── GCS Buckets: {len(demo_gcp['buckets'])}")
    print(f"├── App Engine Services: {len(demo_gcp['app_engine_services'])}")
    print(f"└── Accessible Buckets: {len([b for b in demo_gcp['buckets'] if b['accessible']])}")
    
    # Security findings summary
    print_subsection_header("Security Findings")
    demo_findings = [
        {
            'type': 'Exposed Cloud Storage',
            'severity': 'High',
            'description': '1 publicly accessible cloud storage bucket found'
        },
        {
            'type': 'Multi-Cloud Environment',
            'severity': 'Medium',
            'description': 'Assets found across multiple cloud providers: AWS, Azure, GCP'
        }
    ]
    
    for i, finding in enumerate(demo_findings, 1):
        print(f"{i}. [{finding['severity']}] {finding['type']}")
        print(f"   └── {finding['description']}")
    
    print_subsection_header("Key Features Demonstrated")
    print("✓ AWS S3 bucket enumeration and testing")
    print("✓ Azure blob storage discovery")
    print("✓ Google Cloud storage enumeration")
    print("✓ Cloud metadata service checks")
    print("✓ Multi-cloud security assessment")

def demo_integration_capabilities():
    """Demonstrate how all advanced features work together"""
    print_section_header("INTEGRATED RECONNAISSANCE WORKFLOW")
    
    print("[DEMO] Comprehensive reconnaissance combining all advanced modules")
    
    workflow_steps = [
        "1. Social Engineering Intelligence",
        "   ├── Employee enumeration from public sources",
        "   ├── Email pattern discovery and validation", 
        "   └── Social media correlation",
        "",
        "2. Advanced DNS Intelligence",
        "   ├── DNS over HTTPS bypass testing",
        "   ├── Certificate transparency mining",
        "   └── DNS tunneling detection",
        "",
        "3. Cloud Asset Discovery",
        "   ├── Multi-cloud storage enumeration",
        "   ├── Service discovery across providers",
        "   └── Security configuration assessment",
        "",
        "4. Correlation and Analysis",
        "   ├── Cross-reference discovered assets",
        "   ├── Priority ranking based on exposure",
        "   └── Attack surface mapping"
    ]
    
    for step in workflow_steps:
        print(step)
    
    print_subsection_header("Enhanced Reporting Features")
    print("✓ Executive summary with risk metrics")
    print("✓ Technical findings with remediation steps")
    print("✓ Multi-format output (JSON, HTML, Text)")
    print("✓ Security recommendations prioritized by risk")
    print("✓ Compliance mapping (PCI DSS, ISO 27001)")

def main():
    """Main demo function"""
    print("InfoGather v2.0 - Advanced Reconnaissance Features Demo")
    print("=" * 60)
    print("This demonstration showcases the new advanced capabilities")
    print("added to the InfoGather penetration testing toolkit.")
    print("\nNOTE: This demo shows the framework and structure.")
    print("Full functionality requires appropriate API keys and permissions.")
    
    # Run all demonstrations
    demo_social_engineering()
    demo_advanced_dns()
    demo_cloud_discovery()
    demo_integration_capabilities()
    
    print_section_header("DEMO COMPLETE")
    print("Advanced reconnaissance features successfully demonstrated!")
    print("\nTo use these features with real targets:")
    print("• Ensure you have explicit authorization")
    print("• Configure appropriate API keys")
    print("• Run: python pentester.py -t <target> --advanced-recon")
    print("\nFor help: python pentester.py --help")

if __name__ == "__main__":
    main()