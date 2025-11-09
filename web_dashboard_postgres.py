#!/usr/bin/env python3
"""
InfoGather Web Dashboard with PostgreSQL
Modern web interface for penetration testing and security assessments
"""

from flask import Flask, render_template, request, jsonify, send_file, session, redirect, url_for
import json
import os
import time
import threading
import uuid
import tempfile
from datetime import datetime, timedelta
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps
from models import db, User, Scan, ScanResult, Finding, ScanSummary, AuditLog, init_db

# Import InfoGather modules
from modules.network_scanner import NetworkScanner
from modules.dns_enum import DNSEnumerator
from modules.whois_lookup import WhoisLookup
from modules.ssl_analyzer import SSLAnalyzer
from modules.vulnerability_scanner import VulnerabilityScanner
from modules.social_engineer import SocialEngineer
from modules.advanced_dns import AdvancedDNS
from modules.cloud_discovery import CloudDiscovery
from modules.report_generator import ReportGenerator
from utils.validation import validate_target, validate_ports

app = Flask(__name__)
app.secret_key = os.environ.get('FLASK_SECRET_KEY', os.urandom(24))

# Configure PostgreSQL database
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SQLALCHEMY_ENGINE_OPTIONS'] = {
    'pool_recycle': 300,
    'pool_pre_ping': True,
}

# Initialize database
init_db(app)

# Global variables for scan management
active_scans = {}
scan_results = {}

def require_auth(f):
    """Decorator to require authentication"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

def get_user_info(user_id):
    """Get user information from database"""
    user = User.query.get(user_id)
    return user

@app.route('/')
@require_auth
def index():
    """Main dashboard page"""
    return render_template('dashboard.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    """User login"""
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        user = User.query.filter_by(username=username).first()
        
        if user and check_password_hash(user.password_hash, password):
            session['user_id'] = user.id
            session['username'] = user.username
            user.last_login = datetime.utcnow()
            db.session.commit()
            return redirect(url_for('index'))
        else:
            return render_template('login.html', error='Invalid credentials')
    
    return render_template('login.html')

@app.route('/logout')
def logout():
    """User logout"""
    session.clear()
    return redirect(url_for('login'))

@app.route('/scan')
@require_auth
def scan_page():
    """Scan configuration page"""
    return render_template('scan.html')

@app.route('/api/start_scan', methods=['POST'])
@require_auth
def start_scan():
    """Start a new security scan"""
    data = request.get_json()
    target = data.get('target')
    ports = data.get('ports', '1-1000')
    modules = data.get('modules', [])
    
    if not target:
        return jsonify({'error': 'Target is required'}), 400
    
    if not modules:
        return jsonify({'error': 'At least one module must be selected'}), 400
    
    # Validate target
    if not validate_target(target):
        return jsonify({'error': 'Invalid target format'}), 400
    
    # Create scan record
    scan_id = str(uuid.uuid4())
    scan = Scan()
    scan.id = scan_id
    scan.user_id = session['user_id']
    scan.target = target
    scan.ports = ports
    scan.modules_list = modules
    scan.status = 'running'
    scan.started_at = datetime.utcnow()
    
    db.session.add(scan)
    db.session.commit()
    
    # Start scan in background thread
    thread = threading.Thread(target=run_scan, args=(scan_id, target, ports, modules))
    thread.start()
    
    return jsonify({'scan_id': scan_id})

def run_scan(scan_id, target, ports, modules):
    """Execute the security scan in background"""
    try:
        active_scans[scan_id] = {
            'target': target,
            'status': 'running',
            'progress': 0,
            'current_module': 'Initializing',
            'started_at': datetime.utcnow().isoformat()
        }
        
        results = {}
        total_modules = len(modules)
        
        for i, module in enumerate(modules):
            # Update progress
            progress = int((i / total_modules) * 100)
            active_scans[scan_id]['progress'] = progress
            active_scans[scan_id]['current_module'] = module
            
            # Update database
            scan = Scan.query.get(scan_id)
            if scan:
                scan.progress = progress
                scan.current_module = module
                db.session.commit()
            
            try:
                if module == 'network_scan':
                    scanner = NetworkScanner()
                    results[module] = scanner.scan_target(target, ports)
                
                elif module == 'dns_enum':
                    dns_enum = DNSEnumerator()
                    results[module] = dns_enum.enumerate(target)
                
                elif module == 'whois':
                    whois_lookup = WhoisLookup()
                    results[module] = whois_lookup.lookup(target)
                
                elif module == 'ssl_analysis':
                    ssl_analyzer = SSLAnalyzer()
                    results[module] = ssl_analyzer.analyze(target)
                
                elif module == 'vuln_scan':
                    vuln_scanner = VulnerabilityScanner()
                    results[module] = vuln_scanner.scan(target)
                
                elif module == 'social_intel':
                    social_eng = SocialEngineer()
                    results[module] = social_eng.gather_intelligence(target)
                
                elif module == 'advanced_dns':
                    adv_dns = AdvancedDNS()
                    results[module] = adv_dns.advanced_analysis(target)
                
                elif module == 'cloud_assets':
                    cloud_disc = CloudDiscovery()
                    results[module] = cloud_disc.discover_cloud_assets(target)
                
                # Store result in database
                scan_result = ScanResult(
                    scan_id=scan_id,
                    module_name=module,
                    data=results[module]
                )
                db.session.add(scan_result)
                
            except Exception as e:
                results[module] = {'error': str(e)}
        
        # Generate summary
        summary = generate_scan_summary(results)
        
        # Store summary in database
        scan_summary = ScanSummary(
            scan_id=scan_id,
            total_findings=summary.get('total_findings', 0),
            critical_findings=summary.get('critical_issues', 0),
            high_findings=summary.get('high_issues', 0),
            medium_findings=summary.get('medium_issues', 0),
            low_findings=summary.get('low_issues', 0),
            ports_found=summary.get('ports_found', 0),
            subdomains_found=summary.get('subdomains_found', 0),
            vulnerabilities_found=summary.get('vulnerabilities_found', 0)
        )
        db.session.add(scan_summary)
        
        # Update scan status
        scan = Scan.query.get(scan_id)
        if scan:
            scan.status = 'completed'
            scan.completed_at = datetime.utcnow()
            scan.progress = 100
            scan.current_module = 'Completed'
        
        db.session.commit()
        
        # Store results in memory for quick access
        scan_results[scan_id] = {
            'target': target,
            'started_at': active_scans[scan_id]['started_at'],
            'completed_at': datetime.utcnow().isoformat(),
            'modules_run': modules,
            'findings': results,
            'summary': summary
        }
        
        active_scans[scan_id]['status'] = 'completed'
        
    except Exception as e:
        # Handle scan failure
        scan = Scan.query.get(scan_id)
        if scan:
            scan.status = 'failed'
            scan.error_message = str(e)
            scan.completed_at = datetime.utcnow()
        
        db.session.commit()
        
        if scan_id in active_scans:
            active_scans[scan_id]['status'] = 'failed'
            active_scans[scan_id]['error'] = str(e)

def generate_scan_summary(findings):
    """Generate summary statistics from scan findings"""
    summary = {
        'total_findings': 0,
        'critical_issues': 0,
        'high_issues': 0,
        'medium_issues': 0,
        'low_issues': 0,
        'ports_found': 0,
        'subdomains_found': 0,
        'vulnerabilities_found': 0
    }
    
    for module, data in findings.items():
        if isinstance(data, dict) and 'error' not in data:
            if module == 'network_scan' and 'open_ports' in data:
                summary['ports_found'] = len(data['open_ports'])
            
            elif module == 'dns_enum' and 'subdomains' in data:
                summary['subdomains_found'] = len(data['subdomains'])
            
            elif module == 'vuln_scan' and 'vulnerabilities' in data:
                vulns = data['vulnerabilities']
                summary['vulnerabilities_found'] = len(vulns)
                
                for vuln in vulns:
                    severity = vuln.get('severity', '').lower()
                    if severity == 'critical':
                        summary['critical_issues'] += 1
                    elif severity == 'high':
                        summary['high_issues'] += 1
                    elif severity == 'medium':
                        summary['medium_issues'] += 1
                    elif severity == 'low':
                        summary['low_issues'] += 1
    
    summary['total_findings'] = (summary['critical_issues'] + summary['high_issues'] + 
                               summary['medium_issues'] + summary['low_issues'])
    
    return summary

@app.route('/api/scan_status/<scan_id>')
@require_auth
def get_scan_status(scan_id):
    """Get current scan status"""
    # Check if scan belongs to user
    scan = Scan.query.filter_by(id=scan_id, user_id=session['user_id']).first()
    if not scan:
        return jsonify({'error': 'Scan not found'}), 404
    
    # Return status from active scans or database
    if scan_id in active_scans:
        status_data = active_scans[scan_id].copy()
        status_data['target'] = scan.target
        return jsonify(status_data)
    else:
        return jsonify({
            'target': scan.target,
            'status': scan.status,
            'progress': scan.progress or 0,
            'current_module': scan.current_module or 'Unknown',
            'error': scan.error_message
        })

@app.route('/api/scan_results/<scan_id>')
@require_auth
def get_scan_results(scan_id):
    """Get scan results"""
    # Check if scan belongs to user
    scan = Scan.query.filter_by(id=scan_id, user_id=session['user_id']).first()
    if not scan:
        return jsonify({'error': 'Scan not found'}), 404
    
    # Return from memory if available
    if scan_id in scan_results:
        return jsonify(scan_results[scan_id])
    
    # Reconstruct from database
    results = {}
    scan_result_records = ScanResult.query.filter_by(scan_id=scan_id).all()
    
    for result_record in scan_result_records:
        results[result_record.module_name] = result_record.data
    
    summary_record = ScanSummary.query.filter_by(scan_id=scan_id).first()
    summary = {}
    if summary_record:
        summary = {
            'total_findings': summary_record.total_findings,
            'critical_issues': summary_record.critical_findings,
            'high_issues': summary_record.high_findings,
            'medium_issues': summary_record.medium_findings,
            'low_issues': summary_record.low_findings,
            'ports_found': summary_record.ports_found,
            'subdomains_found': summary_record.subdomains_found,
            'vulnerabilities_found': summary_record.vulnerabilities_found
        }
    
    return jsonify({
        'target': scan.target,
        'started_at': scan.started_at.isoformat() if scan.started_at else None,
        'completed_at': scan.completed_at.isoformat() if scan.completed_at else None,
        'modules_run': scan.modules_list,
        'findings': results,
        'summary': summary
    })

@app.route('/results/<scan_id>')
@require_auth
def results_page(scan_id):
    """Scan results page"""
    # Check if scan belongs to user
    scan = Scan.query.filter_by(id=scan_id, user_id=session['user_id']).first()
    if not scan:
        return redirect(url_for('index'))
    
    return render_template('results.html', scan_id=scan_id)

@app.route('/history')
@require_auth
def history_page():
    """Scan history page"""
    scans = Scan.query.filter_by(user_id=session['user_id']).order_by(Scan.started_at.desc()).all()
    
    # Convert to list of dictionaries for template
    scan_list = []
    for scan in scans:
        scan_dict = {
            'id': scan.id,
            'target': scan.target,
            'modules': scan.modules_list,
            'status': scan.status,
            'started_at': scan.started_at.isoformat() if scan.started_at else None,
            'completed_at': scan.completed_at.isoformat() if scan.completed_at else None
        }
        scan_list.append(scan_dict)
    
    return render_template('history.html', scans=scan_list)

@app.route('/api/export_report/<scan_id>')
@require_auth
def export_report(scan_id):
    """Export scan report in various formats"""
    format_type = request.args.get('format', 'json')
    
    # Check if scan belongs to user
    scan = Scan.query.filter_by(id=scan_id, user_id=session['user_id']).first()
    if not scan:
        return jsonify({'error': 'Scan not found'}), 404
    
    # Get results
    results_response = get_scan_results(scan_id)
    if results_response.status_code != 200:
        return results_response
    
    results = results_response.get_json()
    
    if format_type == 'json':
        import tempfile
        import os
        
        # Create temporary file
        fd, temp_path = tempfile.mkstemp(suffix='.json')
        try:
            with os.fdopen(fd, 'w') as f:
                json.dump(results, f, indent=2)
            
            return send_file(temp_path, as_attachment=True, 
                           download_name=f'infogather_scan_{scan_id}.json',
                           mimetype='application/json')
        finally:
            if os.path.exists(temp_path):
                os.unlink(temp_path)
    
    elif format_type == 'html':
        report_gen = ReportGenerator()
        html_content = report_gen.generate_html_report(results)
        
        fd, temp_path = tempfile.mkstemp(suffix='.html')
        try:
            with os.fdopen(fd, 'w') as f:
                f.write(html_content)
            
            return send_file(temp_path, as_attachment=True,
                           download_name=f'infogather_scan_{scan_id}.html',
                           mimetype='text/html')
        finally:
            if os.path.exists(temp_path):
                os.unlink(temp_path)
    
    else:
        return jsonify({'error': 'Unsupported format'}), 400

@app.route('/api/dashboard_stats')
@require_auth
def dashboard_stats():
    """Get dashboard statistics"""
    user_id = session['user_id']
    
    # Get scan counts
    total_scans = Scan.query.filter_by(user_id=user_id).count()
    completed_scans = Scan.query.filter_by(user_id=user_id, status='completed').count()
    running_scans = Scan.query.filter_by(user_id=user_id, status='running').count()
    
    # Get recent scans
    recent_scans_query = Scan.query.filter_by(user_id=user_id).order_by(Scan.started_at.desc()).limit(5)
    recent_scans = []
    for scan in recent_scans_query:
        recent_scans.append({
            'id': scan.id,
            'target': scan.target,
            'status': scan.status,
            'started_at': scan.started_at.isoformat() if scan.started_at else None
        })
    
    # Generate activity data for chart (last 7 days)
    today = datetime.now()
    activity_data = {
        'labels': [],
        'values': []
    }
    
    for i in range(6, -1, -1):
        date = today - timedelta(days=i)
        date_str = date.strftime('%Y-%m-%d')
        activity_data['labels'].append(date.strftime('%m/%d'))
        
        count = Scan.query.filter(
            Scan.user_id == user_id,
            db.func.date(Scan.started_at) == date_str
        ).count()
        activity_data['values'].append(count)
    
    # Calculate critical findings
    critical_findings = ScanSummary.query.join(Scan).filter(
        Scan.user_id == user_id
    ).with_entities(db.func.sum(ScanSummary.critical_findings)).scalar() or 0
    
    return jsonify({
        'total_scans': total_scans,
        'completed_scans': completed_scans,
        'running_scans': running_scans,
        'critical_findings': critical_findings,
        'recent_scans': recent_scans,
        'activity_data': activity_data,
        'findings_summary': {
            'critical': critical_findings,
            'high': 0,
            'medium': 0,
            'low': 0
        }
    })

@app.route('/api/delete_scan/<scan_id>', methods=['DELETE'])
@require_auth
def delete_scan(scan_id):
    """Delete a scan and its results"""
    # Check ownership
    scan = Scan.query.filter_by(id=scan_id, user_id=session['user_id']).first()
    if not scan:
        return jsonify({'error': 'Unauthorized'}), 403
    
    # Delete from database (cascade will handle related records)
    db.session.delete(scan)
    db.session.commit()
    
    # Clean up memory
    if scan_id in active_scans:
        del active_scans[scan_id]
    if scan_id in scan_results:
        del scan_results[scan_id]
    
    return jsonify({'success': True})

if __name__ == '__main__':
    print("InfoGather Web Dashboard starting...")
    print("Default login: admin / admin123")
    print("Access the dashboard at: http://localhost:5000")
    
    # Use debug mode only in development
    debug_mode = os.environ.get('FLASK_ENV') == 'development'
    # Bind to all interfaces is intentional for containerized/cloud deployment
    app.run(host='0.0.0.0', port=5000, debug=debug_mode)  # nosec B104