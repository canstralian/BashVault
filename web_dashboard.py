#!/usr/bin/env python3
"""
InfoGather Web Dashboard
Modern web interface for penetration testing and security assessments
"""

from flask import Flask, render_template, request, jsonify, send_file, session, redirect, url_for
import json
import os
import time
import threading
import uuid
import os
import sqlite3
from datetime import datetime, timedelta
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps

# Try to import PostgreSQL models, fallback to SQLite
try:
    from models import db, User, Scan, ScanResult, Finding, ScanSummary, AuditLog, init_db
    USE_POSTGRESQL = True
except ImportError:
    USE_POSTGRESQL = False
    print("PostgreSQL models not available, using SQLite fallback")

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

# Configure database based on availability
if USE_POSTGRESQL and os.environ.get('DATABASE_URL'):
    app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL')
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
    app.config['SQLALCHEMY_ENGINE_OPTIONS'] = {
        'pool_recycle': 300,
        'pool_pre_ping': True,
    }
    # Initialize PostgreSQL database
    init_db(app)
else:
    # Fallback to SQLite
    USE_POSTGRESQL = False
    if not os.path.exists('infogather.db'):
        init_sqlite_db()

# Global variables for scan management
active_scans = {}
scan_results = {}
scan_history = []

def require_auth(f):
    """Decorator to require authentication"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

def init_sqlite_db():
    """Initialize SQLite database as fallback"""
    conn = sqlite3.connect('infogather.db')
    cursor = conn.cursor()
    
    # Create tables
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            email TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            last_login TIMESTAMP,
            is_active BOOLEAN DEFAULT 1
        )
    ''')
    
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS scans (
            id TEXT PRIMARY KEY,
            user_id INTEGER REFERENCES users(id),
            target TEXT NOT NULL,
            modules TEXT NOT NULL,
            status TEXT DEFAULT 'pending',
            started_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            completed_at TIMESTAMP,
            progress INTEGER DEFAULT 0,
            current_module TEXT,
            error_message TEXT
        )
    ''')
    
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS scan_results (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_id TEXT REFERENCES scans(id) ON DELETE CASCADE,
            results TEXT NOT NULL
        )
    ''')
    
    # Create default admin user if not exists
    cursor.execute('SELECT id FROM users WHERE username = ?', ('admin',))
    if not cursor.fetchone():
        password_hash = generate_password_hash('admin123')
        cursor.execute(
            'INSERT INTO users (username, password_hash) VALUES (?, ?)',
            ('admin', password_hash)
        )
        print("Created default admin user: admin / admin123")
    
    conn.commit()
    cursor.close()
    conn.close()

def get_user_info(user_id):
    """Get user information from database"""
    if USE_POSTGRESQL:
        user = User.query.get(user_id)
        if user:
            return {'username': user.username, 'email': user.email, 'role': getattr(user, 'role', 'user')}
        return None
    else:
        conn = sqlite3.connect('infogather.db')
        cursor = conn.cursor()
        cursor.execute('SELECT username, email FROM users WHERE id = ?', (user_id,))
        result = cursor.fetchone()
        cursor.close()
        conn.close()
        if result:
            return {'username': result[0], 'email': result[1], 'role': 'user'}
        return None

@app.route('/')
def index():
    """Main dashboard page"""
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    user_info = get_user_info(session['user_id'])
    return render_template('dashboard.html', user=user_info)

@app.route('/login', methods=['GET', 'POST'])
def login():
    """User login"""
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        if USE_POSTGRESQL:
            user = User.query.filter_by(username=username).first()
            if user and check_password_hash(user.password_hash, password):
                session['user_id'] = user.id
                user.last_login = datetime.now()
                db.session.commit()
                return redirect(url_for('index'))
        else:
            conn = sqlite3.connect('infogather.db')
            cursor = conn.cursor()
            cursor.execute('SELECT id, password_hash FROM users WHERE username = ?', (username,))
            result = cursor.fetchone()
            cursor.close()
            conn.close()
            
            if result and check_password_hash(result[1], password):
                session['user_id'] = result[0]
                return redirect(url_for('index'))
        
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
    user_info = get_user_info(session['user_id'])
    return render_template('scan.html', user=user_info)

@app.route('/api/start_scan', methods=['POST'])
@require_auth
def start_scan():
    """Start a new security scan"""
    data = request.get_json()
    
    # Input validation and sanitization
    target = data.get('target', '').strip()
    if not target:
        return jsonify({'error': 'Target is required'}), 400
    
    if len(target) > 255:
        return jsonify({'error': 'Target too long'}), 400
    
    if not validate_target(target):
        return jsonify({'error': 'Invalid target format'}), 400
    
    ports = data.get('ports', '1-1000')
    if not validate_ports(ports):
        return jsonify({'error': 'Invalid port specification'}), 400
    
    modules = data.get('modules', [])
    if not modules or not isinstance(modules, list):
        return jsonify({'error': 'Invalid modules selection'}), 400
    
    # Rate limiting - max 5 concurrent scans per user
    user_active_scans = sum(1 for scan in active_scans.values() 
                           if scan.get('user_id') == session['user_id'] and scan.get('status') == 'running')
    if user_active_scans >= 5:
        return jsonify({'error': 'Too many active scans. Please wait for some to complete.'}), 429
    
    # Generate scan ID
    scan_id = str(uuid.uuid4())
    
    # Store scan in database
    if USE_POSTGRESQL:
        scan = Scan(
            id=scan_id,
            user_id=session['user_id'],
            target=target,
            modules=json.dumps(modules),
            status='running',
            started_at=datetime.now()
        )
        db.session.add(scan)
        db.session.commit()
    else:
        conn = sqlite3.connect('infogather.db')
        cursor = conn.cursor()
        cursor.execute(
            'INSERT INTO scans (id, user_id, target, modules, status, started_at) VALUES (?, ?, ?, ?, ?, ?)',
            (scan_id, session['user_id'], target, json.dumps(modules), 'running', datetime.now())
        )
        conn.commit()
        cursor.close()
        conn.close()
    
    # Initialize scan tracking
    active_scans[scan_id] = {
        'target': target,
        'modules': modules,
        'ports': ports,
        'status': 'running',
        'progress': 0,
        'current_module': None,
        'started_at': datetime.now(),
        'user_id': session['user_id']
    }
    
    # Start scan in background thread
    scan_thread = threading.Thread(target=run_scan, args=(scan_id, target, ports, modules))
    scan_thread.daemon = True
    scan_thread.start()
    
    return jsonify({'scan_id': scan_id, 'status': 'started'})

def run_scan(scan_id, target, ports, modules):
    """Execute the security scan in background"""
    try:
        results = {
            'scan_id': scan_id,
            'target': target,
            'started_at': active_scans[scan_id]['started_at'].isoformat(),
            'modules_run': [],
            'findings': {},
            'summary': {}
        }
        
        total_modules = len(modules)
        completed_modules = 0
        
        # Network scanning
        if 'network_scan' in modules:
            active_scans[scan_id]['current_module'] = 'Network Scan'
            scanner = NetworkScanner(verbose=False)
            network_results = scanner.scan_target(target, ports)
            results['findings']['network_scan'] = network_results
            results['modules_run'].append('Network Scan')
            completed_modules += 1
            active_scans[scan_id]['progress'] = (completed_modules / total_modules) * 100
        
        # DNS enumeration
        if 'dns_enum' in modules:
            active_scans[scan_id]['current_module'] = 'DNS Enumeration'
            dns_enum = DNSEnumerator(verbose=False)
            dns_results = dns_enum.enumerate(target)
            results['findings']['dns_enum'] = dns_results
            results['modules_run'].append('DNS Enumeration')
            completed_modules += 1
            active_scans[scan_id]['progress'] = (completed_modules / total_modules) * 100
        
        # WHOIS lookup
        if 'whois' in modules:
            active_scans[scan_id]['current_module'] = 'WHOIS Lookup'
            whois_lookup = WhoisLookup(verbose=False)
            whois_results = whois_lookup.lookup(target)
            results['findings']['whois'] = whois_results
            results['modules_run'].append('WHOIS Lookup')
            completed_modules += 1
            active_scans[scan_id]['progress'] = (completed_modules / total_modules) * 100
        
        # SSL analysis
        if 'ssl_analysis' in modules:
            active_scans[scan_id]['current_module'] = 'SSL Analysis'
            ssl_analyzer = SSLAnalyzer(verbose=False)
            ssl_results = ssl_analyzer.analyze(target)
            results['findings']['ssl_analysis'] = ssl_results
            results['modules_run'].append('SSL Analysis')
            completed_modules += 1
            active_scans[scan_id]['progress'] = (completed_modules / total_modules) * 100
        
        # Vulnerability scanning
        if 'vuln_scan' in modules:
            active_scans[scan_id]['current_module'] = 'Vulnerability Scan'
            vuln_scanner = VulnerabilityScanner(verbose=False)
            vuln_results = vuln_scanner.scan(target, ports)
            results['findings']['vuln_scan'] = vuln_results
            results['modules_run'].append('Vulnerability Scan')
            completed_modules += 1
            active_scans[scan_id]['progress'] = (completed_modules / total_modules) * 100
        
        # Social engineering intelligence
        if 'social_intel' in modules:
            active_scans[scan_id]['current_module'] = 'Social Intelligence'
            social_engineer = SocialEngineer(verbose=False)
            domain = target if not target.replace('.', '').isdigit() else None
            if domain:
                social_results = social_engineer.gather_intelligence(domain)
                results['findings']['social_intel'] = social_results
            else:
                results['findings']['social_intel'] = {'note': 'Social intelligence requires domain target'}
            results['modules_run'].append('Social Intelligence')
            completed_modules += 1
            active_scans[scan_id]['progress'] = (completed_modules / total_modules) * 100
        
        # Advanced DNS intelligence
        if 'advanced_dns' in modules:
            active_scans[scan_id]['current_module'] = 'Advanced DNS'
            advanced_dns = AdvancedDNS(verbose=False)
            domain = target if not target.replace('.', '').isdigit() else None
            if domain:
                dns_intel_results = advanced_dns.advanced_analysis(domain)
                results['findings']['advanced_dns'] = dns_intel_results
            else:
                results['findings']['advanced_dns'] = {'note': 'Advanced DNS analysis requires domain target'}
            results['modules_run'].append('Advanced DNS')
            completed_modules += 1
            active_scans[scan_id]['progress'] = (completed_modules / total_modules) * 100
        
        # Cloud asset discovery
        if 'cloud_assets' in modules:
            active_scans[scan_id]['current_module'] = 'Cloud Discovery'
            cloud_discovery = CloudDiscovery(verbose=False)
            domain = target if not target.replace('.', '').isdigit() else None
            if domain:
                cloud_results = cloud_discovery.discover_cloud_assets(domain)
                results['findings']['cloud_assets'] = cloud_results
            else:
                results['findings']['cloud_assets'] = {'note': 'Cloud asset discovery requires domain target'}
            results['modules_run'].append('Cloud Discovery')
            completed_modules += 1
            active_scans[scan_id]['progress'] = (completed_modules / total_modules) * 100
        
        # Generate summary
        results['summary'] = generate_scan_summary(results['findings'])
        results['completed_at'] = datetime.now().isoformat()
        
        # Update scan status
        active_scans[scan_id]['status'] = 'completed'
        active_scans[scan_id]['progress'] = 100
        active_scans[scan_id]['current_module'] = None
        
        # Store results
        scan_results[scan_id] = results
        
        # Update database
        if USE_POSTGRESQL:
            scan = Scan.query.get(scan_id)
            if scan:
                scan.status = 'completed'
                scan.completed_at = datetime.now()
                db.session.commit()
                
                # Store results
                scan_result = ScanResult(
                    scan_id=scan_id,
                    results=json.dumps(results)
                )
                db.session.add(scan_result)
                db.session.commit()
        else:
            conn = sqlite3.connect('infogather.db')
            cursor = conn.cursor()
            cursor.execute(
                'UPDATE scans SET status = ?, completed_at = ? WHERE id = ?',
                ('completed', datetime.now(), scan_id)
            )
            cursor.execute(
                'INSERT INTO scan_results (scan_id, results) VALUES (?, ?)',
                (scan_id, json.dumps(results))
            )
            conn.commit()
            cursor.close()
            conn.close()
        
    except Exception as e:
        # Handle scan errors
        active_scans[scan_id]['status'] = 'failed'
        active_scans[scan_id]['error'] = str(e)
        
        conn = sqlite3.connect('infogather.db')
        cursor = conn.cursor()
        cursor.execute(
            'UPDATE scans SET status = ? WHERE id = ?',
            ('failed', scan_id)
        )
        conn.commit()
        conn.close()

def generate_scan_summary(findings):
    """Generate summary statistics from scan findings"""
    summary = {
        'total_findings': 0,
        'critical_issues': 0,
        'high_issues': 0,
        'medium_issues': 0,
        'low_issues': 0,
        'info_issues': 0,
        'ports_found': 0,
        'subdomains_found': 0,
        'vulnerabilities_found': 0
    }
    
    # Count network scan findings
    if 'network_scan' in findings:
        network_data = findings['network_scan']
        if 'open_ports' in network_data:
            summary['ports_found'] = len(network_data['open_ports'])
    
    # Count DNS findings
    if 'dns_enum' in findings:
        dns_data = findings['dns_enum']
        if 'subdomains' in dns_data:
            summary['subdomains_found'] = len(dns_data['subdomains'])
    
    # Count vulnerability findings
    if 'vuln_scan' in findings:
        vuln_data = findings['vuln_scan']
        if 'vulnerabilities' in vuln_data:
            for vuln in vuln_data['vulnerabilities']:
                summary['vulnerabilities_found'] += 1
                severity = vuln.get('severity', 'info').lower()
                if severity == 'critical':
                    summary['critical_issues'] += 1
                elif severity == 'high':
                    summary['high_issues'] += 1
                elif severity == 'medium':
                    summary['medium_issues'] += 1
                elif severity == 'low':
                    summary['low_issues'] += 1
                else:
                    summary['info_issues'] += 1
    
    summary['total_findings'] = (summary['critical_issues'] + summary['high_issues'] + 
                               summary['medium_issues'] + summary['low_issues'] + 
                               summary['info_issues'])
    
    return summary

@app.route('/api/scan_status/<scan_id>')
@require_auth
def get_scan_status(scan_id):
    """Get current scan status"""
    if scan_id not in active_scans:
        return jsonify({'error': 'Scan not found'}), 404
    
    scan_info = active_scans[scan_id]
    
    # Check if user owns this scan
    if scan_info['user_id'] != session['user_id']:
        return jsonify({'error': 'Unauthorized'}), 403
    
    return jsonify({
        'scan_id': scan_id,
        'status': scan_info['status'],
        'progress': scan_info['progress'],
        'current_module': scan_info['current_module'],
        'target': scan_info['target']
    })

@app.route('/api/scan_results/<scan_id>')
@require_auth
def get_scan_results(scan_id):
    """Get scan results"""
    if scan_id not in scan_results:
        return jsonify({'error': 'Results not found'}), 404
    
    # Check ownership through database
    conn = sqlite3.connect('infogather.db')
    cursor = conn.cursor()
    cursor.execute('SELECT user_id FROM scans WHERE id = ?', (scan_id,))
    result = cursor.fetchone()
    conn.close()
    
    if not result or result[0] != session['user_id']:
        return jsonify({'error': 'Unauthorized'}), 403
    
    return jsonify(scan_results[scan_id])

@app.route('/results/<scan_id>')
@require_auth
def results_page(scan_id):
    """Scan results page"""
    user_info = get_user_info(session['user_id'])
    return render_template('results.html', scan_id=scan_id, user=user_info)

@app.route('/history')
@require_auth
def history_page():
    """Scan history page"""
    user_info = get_user_info(session['user_id'])
    
    # Get user's scan history from database
    conn = sqlite3.connect('infogather.db')
    cursor = conn.cursor()
    cursor.execute(
        'SELECT id, target, modules, status, started_at, completed_at FROM scans WHERE user_id = ? ORDER BY started_at DESC',
        (session['user_id'],)
    )
    scans = cursor.fetchall()
    conn.close()
    
    scan_history = []
    for scan in scans:
        scan_history.append({
            'id': scan[0],
            'target': scan[1],
            'modules': json.loads(scan[2]),
            'status': scan[3],
            'started_at': scan[4],
            'completed_at': scan[5]
        })
    
    return render_template('history.html', scans=scan_history, user=user_info)

@app.route('/api/export_report/<scan_id>')
@require_auth
def export_report(scan_id):
    """Export scan report in various formats"""
    if scan_id not in scan_results:
        return jsonify({'error': 'Results not found'}), 404
    
    # Check ownership
    conn = sqlite3.connect('infogather.db')
    cursor = conn.cursor()
    cursor.execute('SELECT user_id FROM scans WHERE id = ?', (scan_id,))
    result = cursor.fetchone()
    conn.close()
    
    if not result or result[0] != session['user_id']:
        return jsonify({'error': 'Unauthorized'}), 403
    
    format_type = request.args.get('format', 'json')
    results = scan_results[scan_id]
    
    if format_type == 'json':
        filename = f"infogather_report_{scan_id}.json"
        with open(filename, 'w') as f:
            json.dump(results, f, indent=2)
        return send_file(filename, as_attachment=True)
    
    elif format_type == 'html':
        # Generate HTML report
        report_generator = ReportGenerator()
        html_content = report_generator.generate_html_report(results)
        filename = f"infogather_report_{scan_id}.html"
        with open(filename, 'w') as f:
            f.write(html_content)
        return send_file(filename, as_attachment=True)
    
    else:
        return jsonify({'error': 'Unsupported format'}), 400

@app.route('/api/dashboard_stats')
@require_auth
def dashboard_stats():
    """Get dashboard statistics"""
    user_id = session['user_id']
    
    conn = sqlite3.connect('infogather.db')
    cursor = conn.cursor()
    
    # Get scan counts
    cursor.execute('SELECT COUNT(*) FROM scans WHERE user_id = ?', (user_id,))
    total_scans = cursor.fetchone()[0]
    
    cursor.execute('SELECT COUNT(*) FROM scans WHERE user_id = ? AND status = ?', (user_id, 'completed'))
    completed_scans = cursor.fetchone()[0]
    
    cursor.execute('SELECT COUNT(*) FROM scans WHERE user_id = ? AND status = ?', (user_id, 'running'))
    running_scans = cursor.fetchone()[0]
    
    # Get recent scans
    cursor.execute(
        'SELECT id, target, status, started_at FROM scans WHERE user_id = ? ORDER BY started_at DESC LIMIT 5',
        (user_id,)
    )
    recent_scans = []
    for row in cursor.fetchall():
        recent_scans.append({
            'id': row[0],
            'target': row[1],
            'status': row[2],
            'started_at': row[3]
        })
    
    # Generate activity data for chart (last 7 days)
    from datetime import datetime, timedelta
    today = datetime.now()
    activity_data = {
        'labels': [],
        'values': []
    }
    
    for i in range(6, -1, -1):
        date = today - timedelta(days=i)
        date_str = date.strftime('%Y-%m-%d')
        activity_data['labels'].append(date.strftime('%m/%d'))
        
        cursor.execute(
            'SELECT COUNT(*) FROM scans WHERE user_id = ? AND DATE(started_at) = ?',
            (user_id, date_str)
        )
        count = cursor.fetchone()[0]
        activity_data['values'].append(count)
    
    conn.close()
    
    # Calculate critical findings (placeholder for now)
    critical_findings = 0
    for scan_id, results in scan_results.items():
        if 'summary' in results:
            critical_findings += results['summary'].get('critical_issues', 0)
    
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
    conn = sqlite3.connect('infogather.db')
    cursor = conn.cursor()
    cursor.execute('SELECT user_id FROM scans WHERE id = ?', (scan_id,))
    result = cursor.fetchone()
    
    if not result or result[0] != session['user_id']:
        conn.close()
        return jsonify({'error': 'Unauthorized'}), 403
    
    # Delete from database
    cursor.execute('DELETE FROM scans WHERE id = ?', (scan_id,))
    conn.commit()
    conn.close()
    
    # Clean up memory
    if scan_id in active_scans:
        del active_scans[scan_id]
    if scan_id in scan_results:
        del scan_results[scan_id]
    
    return jsonify({'success': True})

if __name__ == '__main__':
    # Create database tables
    with app.app_context():
        db.create_all()
        
        # Create default admin user if it doesn't exist
        if not User.query.filter_by(username='admin').first():
            admin_user = User(
                username='admin',
                password_hash=generate_password_hash('admin123')
            )
            db.session.add(admin_user)
            db.session.commit()
            print("Created default admin user: admin / admin123")
    
    # Run the Flask app
    print("InfoGather Web Dashboard starting...")
    print("Default login: admin / admin123")
    print("Access the dashboard at: http://localhost:5000")
    
    app.run(host='0.0.0.0', port=5000, debug=True)