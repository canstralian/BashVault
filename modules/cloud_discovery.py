"""
Cloud Asset Discovery Module
Handles AWS S3 bucket enumeration, Azure blob storage discovery, 
Google Cloud storage enumeration, and cloud metadata service exploitation checks
"""

import requests
import json
import time
import concurrent.futures
from urllib.parse import urljoin, urlparse
import threading
import re
import base64
import hashlib
import dns.resolver
import dns.reversename


class CloudDiscovery:
    def __init__(self, verbose=False, timeout=10):
        """
        Initialize cloud asset discovery module
        
        Args:
            verbose (bool): Enable verbose output
            timeout (int): Request timeout in seconds
        """
        self.verbose = verbose
        self.timeout = timeout
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        })
        
        # Common cloud service patterns
        self.aws_patterns = [
            '{company}',
            '{company}-{env}',
            '{company}-{service}',
            '{company}-backup',
            '{company}-logs',
            '{company}-data',
            '{company}-assets',
            '{company}-static',
            '{company}-media',
            '{company}-documents'
        ]
        
        self.azure_patterns = [
            '{company}',
            '{company}{env}',
            '{company}storage',
            '{company}data',
            '{company}backup',
            '{company}logs'
        ]
        
        self.gcp_patterns = [
            '{company}',
            '{company}-{env}',
            '{company}-storage',
            '{company}-backup',
            '{company}-data'
        ]
        
        # Cloud metadata service endpoints
        self.metadata_endpoints = {
            'aws': 'http://169.254.169.254/latest/meta-data/',
            'azure': 'http://169.254.169.254/metadata/instance?api-version=2021-02-01',
            'gcp': 'http://metadata.google.internal/computeMetadata/v1/',
            'oracle': 'http://169.254.169.254/opc/v1/',
            'digitalocean': 'http://169.254.169.254/metadata/v1/'
        }
        
        # Thread lock for thread-safe operations
        self.lock = threading.Lock()

    def discover_cloud_assets(self, target_domain, company_name=None):
        """
        Perform comprehensive cloud asset discovery
        
        Args:
            target_domain (str): Target domain
            company_name (str): Company name for asset enumeration
            
        Returns:
            dict: Cloud asset discovery results
        """
        if not company_name:
            company_name = target_domain.split('.')[0]
        
        if self.verbose:
            print(f"[INFO] Starting cloud asset discovery for {target_domain}")
        
        results = {
            'target_domain': target_domain,
            'company_name': company_name,
            'aws_assets': {},
            'azure_assets': {},
            'gcp_assets': {},
            'cloud_metadata': {},
            'exposed_buckets': [],
            'security_findings': [],
            'metadata': {
                'scan_time': time.strftime('%Y-%m-%d %H:%M:%S'),
                'discovery_methods': []
            }
        }
        
        # AWS S3 bucket discovery
        aws_results = self._discover_aws_assets(company_name, target_domain)
        results['aws_assets'] = aws_results
        if aws_results.get('buckets'):
            results['metadata']['discovery_methods'].append('AWS S3 Discovery')
        
        # Azure blob storage discovery
        azure_results = self._discover_azure_assets(company_name, target_domain)
        results['azure_assets'] = azure_results
        if azure_results.get('storage_accounts'):
            results['metadata']['discovery_methods'].append('Azure Storage Discovery')
        
        # Google Cloud storage discovery
        gcp_results = self._discover_gcp_assets(company_name, target_domain)
        results['gcp_assets'] = gcp_results
        if gcp_results.get('buckets'):
            results['metadata']['discovery_methods'].append('GCP Storage Discovery')
        
        # Cloud metadata service checks
        metadata_results = self._check_cloud_metadata_services()
        results['cloud_metadata'] = metadata_results
        if any(metadata_results.values()):
            results['metadata']['discovery_methods'].append('Cloud Metadata Analysis')
        
        # Consolidate exposed buckets and security findings
        results['exposed_buckets'] = self._consolidate_exposed_buckets(results)
        results['security_findings'] = self._generate_security_findings(results)
        
        # Generate summary
        results['summary'] = self._generate_discovery_summary(results)
        
        return results

    def _discover_aws_assets(self, company_name, target_domain):
        """Discover AWS S3 buckets and related assets"""
        aws_results = {
            'buckets': [],
            'accessible_buckets': [],
            'bucket_permissions': {},
            'cloudfront_distributions': [],
            'api_gateways': [],
            'load_balancers': []
        }
        
        if self.verbose:
            print(f"[INFO] Discovering AWS assets for {company_name}")
        
        # Generate potential bucket names
        bucket_names = self._generate_bucket_names(company_name, self.aws_patterns)
        
        # Test bucket existence and accessibility
        with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
            future_to_bucket = {
                executor.submit(self._check_s3_bucket, bucket): bucket 
                for bucket in bucket_names
            }
            
            for future in concurrent.futures.as_completed(future_to_bucket):
                bucket_name = future_to_bucket[future]
                try:
                    bucket_info = future.result()
                    if bucket_info:
                        aws_results['buckets'].append(bucket_info)
                        
                        if bucket_info.get('accessible'):
                            aws_results['accessible_buckets'].append(bucket_info)
                        
                        if bucket_info.get('permissions'):
                            aws_results['bucket_permissions'][bucket_name] = bucket_info['permissions']
                            
                except Exception as e:
                    if self.verbose:
                        print(f"[DEBUG] S3 bucket check error for {bucket_name}: {str(e)}")
        
        # Discover CloudFront distributions
        cloudfront_distributions = self._discover_cloudfront_distributions(target_domain)
        aws_results['cloudfront_distributions'] = cloudfront_distributions
        
        # Discover API Gateways
        api_gateways = self._discover_api_gateways(target_domain)
        aws_results['api_gateways'] = api_gateways
        
        # Discover Load Balancers
        load_balancers = self._discover_aws_load_balancers(target_domain)
        aws_results['load_balancers'] = load_balancers
        
        return aws_results

    def _generate_bucket_names(self, company_name, patterns):
        """Generate potential bucket names based on patterns"""
        bucket_names = []
        
        # Clean company name
        clean_company = re.sub(r'[^a-zA-Z0-9-]', '', company_name.lower())
        
        # Common environments and services
        environments = ['dev', 'test', 'staging', 'prod', 'production']
        services = ['web', 'api', 'app', 'db', 'cache', 'cdn']
        
        for pattern in patterns:
            # Base pattern
            try:
                bucket_name = pattern.format(company=clean_company)
                bucket_names.append(bucket_name)
            except:
                continue
            
            # With environments
            for env in environments:
                try:
                    bucket_name = pattern.format(company=clean_company, env=env)
                    bucket_names.append(bucket_name)
                except:
                    continue
            
            # With services
            for service in services:
                try:
                    bucket_name = pattern.format(company=clean_company, service=service)
                    bucket_names.append(bucket_name)
                except:
                    continue
        
        # Add common variations
        variations = [
            f"{clean_company}",
            f"{clean_company}-backup",
            f"{clean_company}-logs", 
            f"{clean_company}-data",
            f"{clean_company}-assets",
            f"{clean_company}-static",
            f"{clean_company}-uploads",
            f"{clean_company}-files",
            f"backup-{clean_company}",
            f"logs-{clean_company}",
            f"data-{clean_company}"
        ]
        
        bucket_names.extend(variations)
        
        return list(set(bucket_names))  # Remove duplicates

    def _check_s3_bucket(self, bucket_name):
        """Check if S3 bucket exists and analyze its accessibility"""
        bucket_info = {
            'name': bucket_name,
            'exists': False,
            'accessible': False,
            'permissions': {},
            'files': [],
            'region': None,
            'security_issues': []
        }
        
        try:
            # Check bucket existence via HTTP
            url = f"https://{bucket_name}.s3.amazonaws.com/"
            response = self.session.head(url, timeout=self.timeout)
            
            if response.status_code == 200:
                bucket_info['exists'] = True
                bucket_info['accessible'] = True
                
                # Get bucket region from headers
                if 'x-amz-bucket-region' in response.headers:
                    bucket_info['region'] = response.headers['x-amz-bucket-region']
                
                # Try to list bucket contents
                list_response = self.session.get(url, timeout=self.timeout)
                if list_response.status_code == 200:
                    bucket_info['permissions']['list'] = True
                    files = self._parse_s3_listing(list_response.text)
                    bucket_info['files'] = files[:50]  # Limit file listing
                    
                    if files:
                        bucket_info['security_issues'].append({
                            'type': 'Public Read Access',
                            'severity': 'High',
                            'description': 'Bucket contents are publicly readable'
                        })
                
                # Test write permissions
                test_key = f"test-{int(time.time())}.txt"
                try:
                    put_response = self.session.put(
                        f"{url}{test_key}",
                        data="test",
                        timeout=self.timeout
                    )
                    if put_response.status_code in [200, 201]:
                        bucket_info['permissions']['write'] = True
                        bucket_info['security_issues'].append({
                            'type': 'Public Write Access',
                            'severity': 'Critical',
                            'description': 'Bucket allows public write access'
                        })
                        
                        # Clean up test file
                        self.session.delete(f"{url}{test_key}")
                except:
                    pass
                    
            elif response.status_code == 403:
                bucket_info['exists'] = True
                bucket_info['accessible'] = False
                
            elif response.status_code == 404:
                # Try alternative region endpoints
                regions = ['us-east-1', 'us-west-2', 'eu-west-1', 'ap-southeast-1']
                for region in regions:
                    region_url = f"https://{bucket_name}.s3.{region}.amazonaws.com/"
                    try:
                        region_response = self.session.head(region_url, timeout=5)
                        if region_response.status_code in [200, 403]:
                            bucket_info['exists'] = True
                            bucket_info['region'] = region
                            if region_response.status_code == 200:
                                bucket_info['accessible'] = True
                            break
                    except:
                        continue
                        
        except Exception as e:
            if self.verbose:
                print(f"[DEBUG] S3 bucket check error for {bucket_name}: {str(e)}")
        
        return bucket_info if bucket_info['exists'] else None

    def _parse_s3_listing(self, xml_content):
        """Parse S3 bucket listing XML"""
        files = []
        
        try:
            import xml.etree.ElementTree as ET
            root = ET.fromstring(xml_content)
            
            # Parse XML namespace
            namespace = {'s3': 'http://s3.amazonaws.com/doc/2006-03-01/'}
            
            for content in root.findall('.//s3:Contents', namespace):
                key_element = content.find('s3:Key', namespace)
                size_element = content.find('s3:Size', namespace)
                modified_element = content.find('s3:LastModified', namespace)
                
                if key_element is not None:
                    file_info = {
                        'key': key_element.text,
                        'size': int(size_element.text) if size_element is not None else 0,
                        'last_modified': modified_element.text if modified_element is not None else None
                    }
                    files.append(file_info)
                    
        except Exception as e:
            if self.verbose:
                print(f"[DEBUG] S3 XML parsing error: {str(e)}")
        
        return files

    def _discover_cloudfront_distributions(self, target_domain):
        """Discover CloudFront distributions for the target domain"""
        distributions = []
        
        try:
            # Look for CloudFront distributions in DNS records
            import dns.resolver
            
            # Check for CNAME records pointing to CloudFront
            try:
                answers = dns.resolver.resolve(target_domain, 'CNAME')
                for answer in answers:
                    cname = str(answer).rstrip('.')
                    if 'cloudfront.net' in cname:
                        distributions.append({
                            'domain': target_domain,
                            'cloudfront_domain': cname,
                            'type': 'CNAME'
                        })
            except:
                pass
            
            # Check www subdomain
            try:
                answers = dns.resolver.resolve(f"www.{target_domain}", 'CNAME')
                for answer in answers:
                    cname = str(answer).rstrip('.')
                    if 'cloudfront.net' in cname:
                        distributions.append({
                            'domain': f"www.{target_domain}",
                            'cloudfront_domain': cname,
                            'type': 'CNAME'
                        })
            except:
                pass
                
        except Exception as e:
            if self.verbose:
                print(f"[DEBUG] CloudFront discovery error: {str(e)}")
        
        return distributions

    def _discover_api_gateways(self, target_domain):
        """Discover AWS API Gateway endpoints"""
        api_gateways = []
        
        # Common API Gateway patterns
        api_patterns = [
            f"api.{target_domain}",
            f"gateway.{target_domain}",
            f"rest.{target_domain}",
            f"v1.{target_domain}",
            f"v2.{target_domain}"
        ]
        
        for pattern in api_patterns:
            try:
                response = self.session.get(f"https://{pattern}", timeout=self.timeout, verify=False)
                
                # Check for API Gateway headers
                if any(header in response.headers for header in ['x-amzn-requestid', 'x-amz-apigw-id']):
                    api_gateways.append({
                        'endpoint': pattern,
                        'status_code': response.status_code,
                        'headers': dict(response.headers),
                        'type': 'API Gateway'
                    })
                    
            except Exception as e:
                if self.verbose:
                    print(f"[DEBUG] API Gateway check error for {pattern}: {str(e)}")
        
        return api_gateways

    def _discover_aws_load_balancers(self, target_domain):
        """Discover AWS Load Balancers"""
        load_balancers = []
        
        try:
            import dns.resolver
            
            # Check A records for ELB patterns
            try:
                answers = dns.resolver.resolve(target_domain, 'A')
                for answer in answers:
                    ip = str(answer)
                    
                    # Try reverse DNS lookup
                    try:
                        reverse_addr = dns.reversename.from_address(ip)
                        reverse_name = dns.resolver.resolve(reverse_addr, 'PTR')
                        for name in reverse_name:
                            name_str = str(name).rstrip('.')
                            if any(elb_pattern in name_str for elb_pattern in ['.elb.', '.elbv2.', '.awsglobalaccelerator.']):
                                load_balancers.append({
                                    'domain': target_domain,
                                    'ip': ip,
                                    'lb_name': name_str,
                                    'type': 'AWS Load Balancer'
                                })
                    except:
                        continue
                        
            except:
                pass
                
        except Exception as e:
            if self.verbose:
                print(f"[DEBUG] Load balancer discovery error: {str(e)}")
        
        return load_balancers

    def _discover_azure_assets(self, company_name, target_domain):
        """Discover Azure blob storage and related assets"""
        azure_results = {
            'storage_accounts': [],
            'accessible_containers': [],
            'blob_services': [],
            'cdn_profiles': [],
            'app_services': []
        }
        
        if self.verbose:
            print(f"[INFO] Discovering Azure assets for {company_name}")
        
        # Generate potential storage account names
        storage_names = self._generate_azure_storage_names(company_name)
        
        # Test storage account existence
        with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
            future_to_storage = {
                executor.submit(self._check_azure_storage, storage): storage 
                for storage in storage_names
            }
            
            for future in concurrent.futures.as_completed(future_to_storage):
                storage_name = future_to_storage[future]
                try:
                    storage_info = future.result()
                    if storage_info:
                        azure_results['storage_accounts'].append(storage_info)
                        
                        if storage_info.get('accessible_containers'):
                            azure_results['accessible_containers'].extend(
                                storage_info['accessible_containers']
                            )
                            
                except Exception as e:
                    if self.verbose:
                        print(f"[DEBUG] Azure storage check error for {storage_name}: {str(e)}")
        
        # Discover Azure CDN
        cdn_profiles = self._discover_azure_cdn(target_domain)
        azure_results['cdn_profiles'] = cdn_profiles
        
        # Discover App Services
        app_services = self._discover_azure_app_services(target_domain)
        azure_results['app_services'] = app_services
        
        return azure_results

    def _generate_azure_storage_names(self, company_name):
        """Generate potential Azure storage account names"""
        storage_names = []
        
        # Clean company name (Azure storage names have restrictions)
        clean_company = re.sub(r'[^a-z0-9]', '', company_name.lower())
        
        # Azure storage patterns
        for pattern in self.azure_patterns:
            try:
                storage_name = pattern.format(company=clean_company)
                # Ensure valid Azure storage name (3-24 chars, lowercase alphanumeric)
                if 3 <= len(storage_name) <= 24 and storage_name.isalnum():
                    storage_names.append(storage_name)
            except:
                continue
        
        return list(set(storage_names))

    def _check_azure_storage(self, storage_name):
        """Check Azure storage account existence and accessibility"""
        storage_info = {
            'name': storage_name,
            'exists': False,
            'accessible_containers': [],
            'blob_endpoints': [],
            'security_issues': []
        }
        
        try:
            # Check blob service endpoint
            blob_url = f"https://{storage_name}.blob.core.windows.net/"
            response = self.session.head(blob_url, timeout=self.timeout)
            
            if response.status_code in [200, 400]:  # 400 indicates exists but no access
                storage_info['exists'] = True
                storage_info['blob_endpoints'].append(blob_url)
                
                # Try to enumerate containers
                list_url = f"{blob_url}?comp=list"
                list_response = self.session.get(list_url, timeout=self.timeout)
                
                if list_response.status_code == 200:
                    containers = self._parse_azure_container_listing(list_response.text)
                    storage_info['accessible_containers'] = containers
                    
                    if containers:
                        storage_info['security_issues'].append({
                            'type': 'Public Container Access',
                            'severity': 'High',
                            'description': 'Storage containers are publicly accessible'
                        })
            
            # Check other service endpoints
            for service in ['queue', 'table', 'file']:
                service_url = f"https://{storage_name}.{service}.core.windows.net/"
                try:
                    service_response = self.session.head(service_url, timeout=5)
                    if service_response.status_code in [200, 400]:
                        storage_info[f'{service}_endpoints'] = [service_url]
                except:
                    continue
                    
        except Exception as e:
            if self.verbose:
                print(f"[DEBUG] Azure storage check error for {storage_name}: {str(e)}")
        
        return storage_info if storage_info['exists'] else None

    def _parse_azure_container_listing(self, xml_content):
        """Parse Azure container listing XML"""
        containers = []
        
        try:
            import xml.etree.ElementTree as ET
            root = ET.fromstring(xml_content)
            
            for container in root.findall('.//Container'):
                name_element = container.find('Name')
                properties = container.find('Properties')
                
                if name_element is not None:
                    container_info = {
                        'name': name_element.text,
                        'last_modified': None,
                        'public_access': None
                    }
                    
                    if properties is not None:
                        last_modified = properties.find('Last-Modified')
                        if last_modified is not None:
                            container_info['last_modified'] = last_modified.text
                    
                    containers.append(container_info)
                    
        except Exception as e:
            if self.verbose:
                print(f"[DEBUG] Azure XML parsing error: {str(e)}")
        
        return containers

    def _discover_azure_cdn(self, target_domain):
        """Discover Azure CDN profiles"""
        cdn_profiles = []
        
        try:
            import dns.resolver
            
            # Check for CNAME records pointing to Azure CDN
            try:
                answers = dns.resolver.resolve(target_domain, 'CNAME')
                for answer in answers:
                    cname = str(answer.target).rstrip('.')
                    if any(cdn_pattern in cname for cdn_pattern in ['.azureedge.net', '.azure.com']):
                        cdn_profiles.append({
                            'domain': target_domain,
                            'cdn_endpoint': cname,
                            'type': 'Azure CDN'
                        })
            except:
                pass
                
        except Exception as e:
            if self.verbose:
                print(f"[DEBUG] Azure CDN discovery error: {str(e)}")
        
        return cdn_profiles

    def _discover_azure_app_services(self, target_domain):
        """Discover Azure App Services"""
        app_services = []
        
        # Common App Service patterns
        app_patterns = [
            target_domain.replace('.', '-'),
            f"{target_domain.split('.')[0]}-app",
            f"{target_domain.split('.')[0]}-web",
            f"{target_domain.split('.')[0]}-api"
        ]
        
        for pattern in app_patterns:
            try:
                app_url = f"https://{pattern}.azurewebsites.net"
                response = self.session.head(app_url, timeout=self.timeout)
                
                if response.status_code in [200, 403, 404]:
                    app_services.append({
                        'name': pattern,
                        'url': app_url,
                        'status_code': response.status_code,
                        'headers': dict(response.headers)
                    })
                    
            except Exception as e:
                if self.verbose:
                    print(f"[DEBUG] Azure App Service check error for {pattern}: {str(e)}")
        
        return app_services

    def _discover_gcp_assets(self, company_name, target_domain):
        """Discover Google Cloud Platform assets"""
        gcp_results = {
            'buckets': [],
            'accessible_buckets': [],
            'app_engine_services': [],
            'cloud_functions': [],
            'cloud_storage': []
        }
        
        if self.verbose:
            print(f"[INFO] Discovering GCP assets for {company_name}")
        
        # Generate potential bucket names
        bucket_names = self._generate_bucket_names(company_name, self.gcp_patterns)
        
        # Test GCS bucket existence
        with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
            future_to_bucket = {
                executor.submit(self._check_gcs_bucket, bucket): bucket 
                for bucket in bucket_names
            }
            
            for future in concurrent.futures.as_completed(future_to_bucket):
                bucket_name = future_to_bucket[future]
                try:
                    bucket_info = future.result()
                    if bucket_info:
                        gcp_results['buckets'].append(bucket_info)
                        
                        if bucket_info.get('accessible'):
                            gcp_results['accessible_buckets'].append(bucket_info)
                            
                except Exception as e:
                    if self.verbose:
                        print(f"[DEBUG] GCS bucket check error for {bucket_name}: {str(e)}")
        
        # Discover App Engine services
        app_engine_services = self._discover_app_engine(target_domain)
        gcp_results['app_engine_services'] = app_engine_services
        
        # Discover Cloud Functions
        cloud_functions = self._discover_cloud_functions(target_domain)
        gcp_results['cloud_functions'] = cloud_functions
        
        return gcp_results

    def _check_gcs_bucket(self, bucket_name):
        """Check Google Cloud Storage bucket existence and accessibility"""
        bucket_info = {
            'name': bucket_name,
            'exists': False,
            'accessible': False,
            'files': [],
            'security_issues': []
        }
        
        try:
            # Check bucket existence
            url = f"https://storage.googleapis.com/storage/v1/b/{bucket_name}"
            response = self.session.get(url, timeout=self.timeout)
            
            if response.status_code == 200:
                bucket_info['exists'] = True
                bucket_data = response.json()
                
                # Try to list objects
                objects_url = f"https://storage.googleapis.com/storage/v1/b/{bucket_name}/o"
                objects_response = self.session.get(objects_url, timeout=self.timeout)
                
                if objects_response.status_code == 200:
                    bucket_info['accessible'] = True
                    objects_data = objects_response.json()
                    
                    if 'items' in objects_data:
                        bucket_info['files'] = objects_data['items'][:50]  # Limit files
                        
                        bucket_info['security_issues'].append({
                            'type': 'Public Read Access',
                            'severity': 'High',
                            'description': 'GCS bucket contents are publicly readable'
                        })
                        
            elif response.status_code == 403:
                bucket_info['exists'] = True
                bucket_info['accessible'] = False
                
        except Exception as e:
            if self.verbose:
                print(f"[DEBUG] GCS bucket check error for {bucket_name}: {str(e)}")
        
        return bucket_info if bucket_info['exists'] else None

    def _discover_app_engine(self, target_domain):
        """Discover Google App Engine services"""
        app_engine_services = []
        
        # Common App Engine patterns
        company_name = target_domain.split('.')[0]
        app_patterns = [
            f"{company_name}.appspot.com",
            f"{company_name}-app.appspot.com",
            f"{company_name}-api.appspot.com",
            f"{company_name}-web.appspot.com"
        ]
        
        for pattern in app_patterns:
            try:
                app_url = f"https://{pattern}"
                response = self.session.head(app_url, timeout=self.timeout)
                
                if response.status_code in [200, 403, 404]:
                    app_engine_services.append({
                        'service': pattern,
                        'url': app_url,
                        'status_code': response.status_code,
                        'headers': dict(response.headers)
                    })
                    
            except Exception as e:
                if self.verbose:
                    print(f"[DEBUG] App Engine check error for {pattern}: {str(e)}")
        
        return app_engine_services

    def _discover_cloud_functions(self, target_domain):
        """Discover Google Cloud Functions"""
        cloud_functions = []
        
        # Note: Cloud Functions discovery is limited without API access
        # This would require Google Cloud API credentials for comprehensive discovery
        
        cloud_functions.append({
            'note': 'Cloud Functions discovery requires Google Cloud API credentials',
            'recommendation': 'Use Google Cloud Asset Inventory API for comprehensive discovery'
        })
        
        return cloud_functions

    def _check_cloud_metadata_services(self):
        """Check for accessible cloud metadata services"""
        metadata_results = {}
        
        if self.verbose:
            print("[INFO] Checking cloud metadata service accessibility")
        
        for provider, endpoint in self.metadata_endpoints.items():
            try:
                headers = {}
                if provider == 'azure':
                    headers['Metadata'] = 'true'
                elif provider == 'gcp':
                    headers['Metadata-Flavor'] = 'Google'
                
                response = self.session.get(
                    endpoint, 
                    timeout=5, 
                    headers=headers,
                    verify=False
                )
                
                if response.status_code == 200:
                    metadata_results[provider] = {
                        'accessible': True,
                        'endpoint': endpoint,
                        'response_size': len(response.content),
                        'headers': dict(response.headers),
                        'sample_data': response.text[:500] if response.text else None
                    }
                    
                    if self.verbose:
                        print(f"[WARN] {provider.upper()} metadata service accessible!")
                        
                else:
                    metadata_results[provider] = {
                        'accessible': False,
                        'endpoint': endpoint,
                        'status_code': response.status_code
                    }
                    
            except Exception as e:
                metadata_results[provider] = {
                    'accessible': False,
                    'endpoint': endpoint,
                    'error': str(e)
                }
        
        return metadata_results

    def _consolidate_exposed_buckets(self, results):
        """Consolidate all exposed/accessible cloud storage buckets"""
        exposed_buckets = []
        
        # AWS S3 buckets
        for bucket in results.get('aws_assets', {}).get('accessible_buckets', []):
            exposed_buckets.append({
                'provider': 'AWS S3',
                'name': bucket['name'],
                'url': f"https://{bucket['name']}.s3.amazonaws.com/",
                'permissions': bucket.get('permissions', {}),
                'file_count': len(bucket.get('files', [])),
                'security_issues': bucket.get('security_issues', [])
            })
        
        # Azure Storage
        for storage in results.get('azure_assets', {}).get('storage_accounts', []):
            if storage.get('accessible_containers'):
                exposed_buckets.append({
                    'provider': 'Azure Storage',
                    'name': storage['name'],
                    'url': f"https://{storage['name']}.blob.core.windows.net/",
                    'containers': len(storage['accessible_containers']),
                    'security_issues': storage.get('security_issues', [])
                })
        
        # GCP Storage
        for bucket in results.get('gcp_assets', {}).get('accessible_buckets', []):
            exposed_buckets.append({
                'provider': 'Google Cloud Storage',
                'name': bucket['name'],
                'url': f"https://storage.googleapis.com/{bucket['name']}/",
                'file_count': len(bucket.get('files', [])),
                'security_issues': bucket.get('security_issues', [])
            })
        
        return exposed_buckets

    def _generate_security_findings(self, results):
        """Generate security findings from cloud asset discovery"""
        findings = []
        
        # Exposed buckets
        exposed_count = len(results.get('exposed_buckets', []))
        if exposed_count > 0:
            findings.append({
                'type': 'Exposed Cloud Storage',
                'severity': 'High',
                'description': f'{exposed_count} publicly accessible cloud storage buckets found',
                'recommendation': 'Review and restrict bucket permissions immediately'
            })
        
        # Accessible metadata services
        accessible_metadata = [
            provider for provider, data in results.get('cloud_metadata', {}).items()
            if data.get('accessible', False)
        ]
        
        if accessible_metadata:
            findings.append({
                'type': 'Cloud Metadata Service Exposure',
                'severity': 'Critical',
                'description': f'Cloud metadata services accessible: {", ".join(accessible_metadata)}',
                'recommendation': 'Implement proper network segmentation and access controls'
            })
        
        # Multiple cloud providers
        active_providers = []
        if results.get('aws_assets', {}).get('buckets'):
            active_providers.append('AWS')
        if results.get('azure_assets', {}).get('storage_accounts'):
            active_providers.append('Azure')
        if results.get('gcp_assets', {}).get('buckets'):
            active_providers.append('GCP')
        
        if len(active_providers) > 1:
            findings.append({
                'type': 'Multi-Cloud Environment',
                'severity': 'Medium',
                'description': f'Assets found across multiple cloud providers: {", ".join(active_providers)}',
                'recommendation': 'Ensure consistent security policies across all cloud platforms'
            })
        
        return findings

    def _generate_discovery_summary(self, results):
        """Generate summary of cloud asset discovery"""
        summary = {
            'total_discovery_methods': len(results['metadata']['discovery_methods']),
            'aws_buckets_found': len(results.get('aws_assets', {}).get('buckets', [])),
            'azure_storage_found': len(results.get('azure_assets', {}).get('storage_accounts', [])),
            'gcp_buckets_found': len(results.get('gcp_assets', {}).get('buckets', [])),
            'exposed_buckets': len(results.get('exposed_buckets', [])),
            'security_findings': len(results.get('security_findings', [])),
            'metadata_services_accessible': sum(
                1 for data in results.get('cloud_metadata', {}).values()
                if data.get('accessible', False)
            )
        }
        
        return summary