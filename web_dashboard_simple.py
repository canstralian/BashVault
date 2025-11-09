#!/usr/bin/env python3
"""
InfoGather Web Dashboard with PostgreSQL
Simplified version with PostgreSQL integration
"""

from flask import Flask, render_template, request, jsonify, session, redirect, url_for
import json
import os
import threading
import uuid
import time
from datetime import datetime
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps
import psycopg2
from psycopg2.extras import RealDictCursor
import secrets
import atexit
from contextlib import contextmanager

# Import InfoGather modules
from modules.network_scanner import NetworkScanner
from modules.dns_enum import DNSEnumerator
from modules.whois_lookup import WhoisLookup
from modules.ssl_analyzer import SSLAnalyzer
from modules.vulnerability_scanner import VulnerabilityScanner
from modules.social_engineer import SocialEngineer
from modules.advanced_dns import AdvancedDNS
from modules.cloud_discovery import CloudDiscovery
from modules.threat_monitor import ThreatMonitor
from utils.validation import validate_target, validate_ports
from schemas import ScanRequestSchema, LoginSchema, validate_request_data

app = Flask(__name__)
# Generate secure secret key if not provided
if 'FLASK_SECRET_KEY' not in os.environ:
    os.environ['FLASK_SECRET_KEY'] = secrets.token_hex(32)
app.secret_key = os.environ.get('FLASK_SECRET_KEY')

# Thread-safe global variables for scan management
active_scans = {}
scan_results = {}
scans_lock = threading.RLock()
results_lock = threading.RLock()

# Use DATABASE_URL from environment (provided by Replit PostgreSQL)
DATABASE_URL = os.environ.get('DATABASE_URL')

def get_db_config():
    """Parse DATABASE_URL into connection parameters"""
    if DATABASE_URL:
        # Parse postgres://user:pass@host:port/dbname
        import urllib.parse
        parsed = urllib.parse.urlparse(DATABASE_URL)
        return {
            'host': parsed.hostname,
            'database': parsed.path[1:],  # Remove leading /
            'user': parsed.username,
            'password': parsed.password,
            'port': parsed.port or 5432
        }
    else:
        # Fallback configuration
        return {
            'host': os.environ.get('PGHOST', 'localhost'),
            'database': os.environ.get('PGDATABASE', 'infogather'),
            'user': os.environ.get('PGUSER', 'postgres'),
            'password': os.environ.get('PGPASSWORD', ''),
            'port': int(os.environ.get('PGPORT', 5432))
        }

# Initialize threat monitor
threat_monitor = ThreatMonitor(verbose=True)
threat_monitor.start_monitoring(check_interval=300)  # Check every 5 minutes

@contextmanager
def get_db_connection():
    """Context manager for database connections"""
    conn = None
    try:
        db_config = get_db_config()
        conn = psycopg2.connect(**db_config)
        yield conn
    except Exception as e:
        if conn:
            conn.rollback()
        raise e
    finally:
        if conn:
            conn.close()

# Register cleanup function for application shutdown
@atexit.register
def cleanup():
    """Cleanup resources on application shutdown"""
    try:
        print("Application cleanup completed")
    except Exception as e:
        print(f"Cleanup error: {e}")

def init_database():
    """Initialize PostgreSQL database tables"""
    try:
        with get_db_connection() as conn:
            cursor = conn.cursor()
            
            # Create users table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS users (
                    id SERIAL PRIMARY KEY,
                    username VARCHAR(80) UNIQUE NOT NULL,
                    password_hash VARCHAR(255) NOT NULL,
                    email VARCHAR(120),
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    last_login TIMESTAMP,
                    is_active BOOLEAN DEFAULT TRUE
                )
            ''')
            
            # Create scans table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS scans (
                    id VARCHAR(36) PRIMARY KEY,
                    user_id INTEGER REFERENCES users(id),
                    target VARCHAR(255) NOT NULL,
                    ports VARCHAR(100),
                    modules TEXT NOT NULL,
                    status VARCHAR(20) DEFAULT 'pending',
                    started_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    completed_at TIMESTAMP,
                    progress INTEGER DEFAULT 0,
                    current_module VARCHAR(50),
                    error_message TEXT
                )
            ''')
            
            # Create scan_results table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS scan_results (
                    id SERIAL PRIMARY KEY,
                    scan_id VARCHAR(36) REFERENCES scans(id) ON DELETE CASCADE,
                    module_name VARCHAR(50) NOT NULL,
                    result_data TEXT NOT NULL,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            ''')
            
            # Create default admin user if it doesn't exist
            cursor.execute('SELECT id FROM users WHERE username = %s', ('admin',))
            if not cursor.fetchone():
                # Use environment variable for admin password or generate secure random password
                admin_password = os.environ.get('ADMIN_PASSWORD')
                if not admin_password:
                    admin_password = secrets.token_urlsafe(16)
                    print(f"Generated admin password: {admin_password}")
                    print("Store this password securely - it will not be displayed again!")
                
                password_hash = generate_password_hash(admin_password)
                cursor.execute(
                    'INSERT INTO users (username, password_hash, is_active) VALUES (%s, %s, %s)',
                    ('admin', password_hash, True)
                )
                print("Created default admin user with secure password")
            
            conn.commit()
            cursor.close()
            
    except Exception as e:
        print(f"Database initialization error: {e}")
        raise

def require_auth(f):
    """Decorator to require authentication"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

@app.route('/')
@require_auth
def index():
    """Main dashboard page"""
    return render_template('dashboard.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    """User login"""
    if request.method == 'POST':
        # Get form data
        form_data = {
            'username': request.form.get('username', '').strip(),
            'password': request.form.get('password', '')
        }
        
        # Validate input using Marshmallow schema
        validated_data, errors = validate_request_data(LoginSchema, form_data)
        if errors:
            error_msg = '; '.join([f"{k}: {', '.join(v)}" for k, v in errors.items()])
            return render_template('login.html', error=error_msg)
        
        username = validated_data['username']
        password = validated_data['password']
        
        try:
            with get_db_connection() as conn:
                cursor = conn.cursor(cursor_factory=RealDictCursor)
                cursor.execute('SELECT * FROM users WHERE username = %s AND is_active = TRUE', (username,))
                user = cursor.fetchone()
                cursor.close()
                
                if user and check_password_hash(user['password_hash'], password):
                    session['user_id'] = user['id']
                    session['username'] = user['username']
                    
                    # Update last login
                    cursor = conn.cursor()
                    cursor.execute('UPDATE users SET last_login = %s WHERE id = %s', 
                                 (datetime.utcnow(), user['id']))
                    conn.commit()
                    cursor.close()
                    
                    return redirect(url_for('index'))
                else:
                    return render_template('login.html', error='Invalid credentials')
                    
        except Exception as e:
            print(f"Login error: {e}")
            return render_template('login.html', error='Login system temporarily unavailable')
    
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
    try:
        data = request.get_json()
        if not data:
            return jsonify({'error': 'No data provided'}), 400
        
        # Validate input using Marshmallow schema
        validated_data, errors = validate_request_data(ScanRequestSchema, data)
        if errors:
            return jsonify({'error': 'Validation failed', 'details': errors}), 400
        
        target = validated_data['target']
        ports = validated_data['ports']
        modules = validated_data['modules']
        
        # Create scan record
        scan_id = str(uuid.uuid4())
        
        try:
            with get_db_connection() as conn:
                cursor = conn.cursor()
                
                cursor.execute('''
                    INSERT INTO scans (id, user_id, target, ports, modules, status, started_at)
                    VALUES (%s, %s, %s, %s, %s, %s, %s)
                ''', (scan_id, session['user_id'], target, ports, json.dumps(modules), 'running', datetime.utcnow()))
                
                conn.commit()
                cursor.close()
                
                # Add to active scans with thread safety
                with scans_lock:
                    active_scans[scan_id] = {
                        'target': target,
                        'status': 'starting',
                        'progress': 0,
                        'current_module': 'Initializing',
                        'started_at': datetime.utcnow().isoformat()
                    }
                
                # Start scan in background thread
                thread = threading.Thread(target=run_scan, args=(scan_id, target, ports, modules))
                thread.daemon = True
                thread.start()
                
                return jsonify({'scan_id': scan_id})
                
        except Exception as e:
            print(f"Database error in start_scan: {e}")
            return jsonify({'error': 'Failed to create scan'}), 500
                
    except Exception as e:
        print(f"Error in start_scan: {e}")
        return jsonify({'error': 'Internal server error'}), 500

def run_scan(scan_id, target, ports, modules):
    """Execute the security scan in background"""
    try:
        # Initialize scan status with thread safety
        with scans_lock:
            if scan_id in active_scans:
                active_scans[scan_id]['status'] = 'running'
        
        results = {}
        total_modules = len(modules)
        
        for i, module in enumerate(modules):
            # Update progress with thread safety
            progress = int((i / total_modules) * 100)
            with scans_lock:
                if scan_id in active_scans:
                    active_scans[scan_id]['progress'] = progress
                    active_scans[scan_id]['current_module'] = module
            
            # Update database
            try:
                with get_db_connection() as conn:
                    cursor = conn.cursor()
                    cursor.execute('''
                        UPDATE scans SET progress = %s, current_module = %s WHERE id = %s
                    ''', (progress, module, scan_id))
                    conn.commit()
                    cursor.close()
            except Exception as db_e:
                print(f"Database update error: {db_e}")
            
            # Execute module scan
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
                    results[module] = ssl_analyzer.analyze(target, None)
                
                elif module == 'vuln_scan':
                    vuln_scanner = VulnerabilityScanner()
                    results[module] = vuln_scanner.scan(target, ports)
                
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
                try:
                    with get_db_connection() as conn:
                        cursor = conn.cursor()
                        cursor.execute('''
                            INSERT INTO scan_results (scan_id, module_name, result_data)
                            VALUES (%s, %s, %s)
                        ''', (scan_id, module, json.dumps(results[module], default=str)))
                        conn.commit()
                        cursor.close()
                except Exception as db_e:
                    print(f"Result storage error: {db_e}")
                
            except Exception as e:
                print(f"Module {module} execution error: {e}")
                results[module] = {'error': str(e)}
        
        # Generate summary
        summary = generate_scan_summary(results)
        
        # Update scan status to completed
        try:
            with get_db_connection() as conn:
                cursor = conn.cursor()
                cursor.execute('''
                    UPDATE scans SET status = %s, completed_at = %s, progress = %s, current_module = %s
                    WHERE id = %s
                ''', ('completed', datetime.utcnow(), 100, 'Completed', scan_id))
                conn.commit()
                cursor.close()
        except Exception as db_e:
            print(f"Completion update error: {db_e}")
        
        # Store results in memory for quick access with thread safety
        with results_lock:
            scan_results[scan_id] = {
                'target': target,
                'started_at': active_scans.get(scan_id, {}).get('started_at', datetime.utcnow().isoformat()),
                'completed_at': datetime.utcnow().isoformat(),
                'modules_run': modules,
                'findings': results,
                'summary': summary
            }
        
        # Add target to threat monitoring
        try:
            if target.replace('.', '').replace(':', '').isdigit():
                threat_monitor.add_monitored_asset('ip', target)
            else:
                threat_monitor.add_monitored_asset('domain', target)
        except Exception as e:
            print(f"Failed to add {target} to monitoring: {str(e)}")
        
        # Update active scan status
        with scans_lock:
            if scan_id in active_scans:
                active_scans[scan_id]['status'] = 'completed'
        
    except Exception as e:
        print(f"Scan execution error: {e}")
        # Handle scan failure
        try:
            with get_db_connection() as conn:
                cursor = conn.cursor()
                cursor.execute('''
                    UPDATE scans SET status = %s, error_message = %s, completed_at = %s
                    WHERE id = %s
                ''', ('failed', str(e), datetime.utcnow(), scan_id))
                conn.commit()
                cursor.close()
        except Exception as db_e:
            print(f"Error update failed: {db_e}")
        
        # Update active scan status
        with scans_lock:
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
    with get_db_connection() as conn:
        cursor = conn.cursor(cursor_factory=RealDictCursor)
        cursor.execute('SELECT * FROM scans WHERE id = %s AND user_id = %s', (scan_id, session['user_id']))
        scan = cursor.fetchone()
        cursor.close()
    
    if not scan:
        return jsonify({'error': 'Scan not found'}), 404
    
    # Return status from active scans or database
    if scan_id in active_scans:
        status_data = active_scans[scan_id].copy()
        status_data['target'] = scan['target']
        return jsonify(status_data)
    else:
        return jsonify({
            'target': scan['target'],
            'status': scan['status'],
            'progress': scan['progress'] or 0,
            'current_module': scan['current_module'] or 'Unknown',
            'error': scan['error_message']
        })

@app.route('/api/scan_results/<scan_id>')
@require_auth
def get_scan_results(scan_id):
    """Get scan results"""
    # Check if scan belongs to user
    with get_db_connection() as conn:
        cursor = conn.cursor(cursor_factory=RealDictCursor)
        cursor.execute('SELECT * FROM scans WHERE id = %s AND user_id = %s', (scan_id, session['user_id']))
        scan = cursor.fetchone()
        
        if not scan:
            cursor.close()
            return jsonify({'error': 'Scan not found'}), 404
        
        # Return from memory if available
        if scan_id in scan_results:
            cursor.close()
            return jsonify(scan_results[scan_id])
        
        # Reconstruct from database
        cursor.execute('SELECT * FROM scan_results WHERE scan_id = %s', (scan_id,))
        result_records = cursor.fetchall()
        cursor.close()
    
    results = {}
    for record in result_records:
        try:
            results[record['module_name']] = json.loads(record['result_data'])
        except json.JSONDecodeError:
            results[record['module_name']] = {'error': 'Invalid result data'}
    
    summary = generate_scan_summary(results)
    
    return jsonify({
        'target': scan['target'],
        'started_at': scan['started_at'].isoformat() if scan['started_at'] else None,
        'completed_at': scan['completed_at'].isoformat() if scan['completed_at'] else None,
        'modules_run': json.loads(scan['modules']) if scan['modules'] else [],
        'findings': results,
        'summary': summary
    })

@app.route('/results/<scan_id>')
@require_auth
def results_page(scan_id):
    """Scan results page"""
    # Check if scan belongs to user
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute('SELECT id FROM scans WHERE id = %s AND user_id = %s', (scan_id, session['user_id']))
        scan = cursor.fetchone()
        cursor.close()
    
    if not scan:
        return redirect(url_for('index'))
    
    return render_template('results.html', scan_id=scan_id)

@app.route('/history')
@require_auth
def history_page():
    """Scan history page"""
    with get_db_connection() as conn:
        cursor = conn.cursor(cursor_factory=RealDictCursor)
        cursor.execute('''
            SELECT * FROM scans WHERE user_id = %s ORDER BY started_at DESC
        ''', (session['user_id'],))
        scans = cursor.fetchall()
        cursor.close()
    
    # Convert to list of dictionaries for template
    scan_list = []
    for scan in scans:
        scan_dict = {
            'id': scan['id'],
            'target': scan['target'],
            'modules': json.loads(scan['modules']) if scan['modules'] else [],
            'status': scan['status'],
            'started_at': scan['started_at'].isoformat() if scan['started_at'] else None,
            'completed_at': scan['completed_at'].isoformat() if scan['completed_at'] else None
        }
        scan_list.append(scan_dict)
    
    return render_template('history.html', scans=scan_list)

@app.route('/api/dashboard_stats')
@require_auth
def dashboard_stats():
    """Get dashboard statistics"""
    user_id = session['user_id']
    
    with get_db_connection() as conn:
        cursor = conn.cursor()
        
        # Get scan counts
        cursor.execute('SELECT COUNT(*) FROM scans WHERE user_id = %s', (user_id,))
        total_scans = cursor.fetchone()[0]
        
        cursor.execute('SELECT COUNT(*) FROM scans WHERE user_id = %s AND status = %s', (user_id, 'completed'))
        completed_scans = cursor.fetchone()[0]
        
        cursor.execute('SELECT COUNT(*) FROM scans WHERE user_id = %s AND status = %s', (user_id, 'running'))
        running_scans = cursor.fetchone()[0]
        
        # Get recent scans
        cursor.execute('''
            SELECT id, target, status, started_at FROM scans 
            WHERE user_id = %s ORDER BY started_at DESC LIMIT 5
        ''', (user_id,))
        recent_scans_rows = cursor.fetchall()
        
        recent_scans = []
        for row in recent_scans_rows:
            recent_scans.append({
                'id': row[0],
                'target': row[1],
                'status': row[2],
                'started_at': row[3].isoformat() if row[3] else None
            })
        
        cursor.close()
        
        # Generate activity data for chart (simplified)
        activity_data = {
            'labels': ['Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat', 'Sun'],
            'values': [0, 1, 2, 1, 3, 1, 0]  # Sample data
        }
        
        # Get monitoring stats
        monitoring_stats = threat_monitor.get_monitoring_stats()
        recent_alerts = threat_monitor.get_alerts(status='new', limit=5)
        
        return jsonify({
            'total_scans': total_scans,
            'completed_scans': completed_scans,
            'running_scans': running_scans,
            'critical_findings': monitoring_stats.get('new_alerts', 0),
            'recent_scans': recent_scans,
            'activity_data': activity_data,
            'findings_summary': {
                'critical': 0,
                'high': 0,
                'medium': 0,
                'low': 0
            },
            'monitoring_stats': monitoring_stats,
            'recent_alerts': recent_alerts
        })

@app.route('/api/delete_scan/<scan_id>', methods=['DELETE'])
@require_auth
def delete_scan(scan_id):
    """Delete a scan and its results"""
    # Check ownership and delete
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute('DELETE FROM scans WHERE id = %s AND user_id = %s', (scan_id, session['user_id']))
        
        if cursor.rowcount == 0:
            cursor.close()
            return jsonify({'error': 'Unauthorized or scan not found'}), 403
        
        conn.commit()
        cursor.close()
    
    # Clean up memory
    if scan_id in active_scans:
        del active_scans[scan_id]
    if scan_id in scan_results:
        del scan_results[scan_id]
    
    return jsonify({'success': True})

@app.route('/api/threat_monitor/stats')
@require_auth
def get_threat_monitor_stats():
    """Get threat monitoring statistics"""
    stats = threat_monitor.get_monitoring_stats()
    return jsonify(stats)

@app.route('/api/threat_monitor/alerts')
@require_auth
def get_threat_alerts():
    """Get current threat alerts"""
    status = request.args.get('status', 'new')
    limit = int(request.args.get('limit', 20))
    alerts = threat_monitor.get_alerts(status=status, limit=limit)
    return jsonify({'alerts': alerts})

@app.route('/api/threat_monitor/alerts/<int:alert_id>/read', methods=['POST'])
@require_auth
def mark_alert_read(alert_id):
    """Mark an alert as read"""
    success = threat_monitor.mark_alert_read(alert_id)
    return jsonify({'success': success})

@app.route('/api/threat_monitor/add_asset', methods=['POST'])
@require_auth
def add_monitored_asset():
    """Add an asset to continuous monitoring"""
    data = request.get_json()
    asset_type = data.get('type')
    asset_value = data.get('value')
    
    if not asset_type or not asset_value:
        return jsonify({'error': 'Asset type and value are required'}), 400
    
    success = threat_monitor.add_monitored_asset(asset_type, asset_value)
    return jsonify({'success': success})

@app.route('/monitoring')
@require_auth
def monitoring_page():
    """Real-time monitoring dashboard page"""
    return render_template('monitoring.html')

@app.route('/health')
def health_check():
    """Health check endpoint for monitoring"""
    try:
        # Check database connectivity
        with get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT 1")
            cursor.fetchone()
            cursor.close()
            
        # Check threat monitor status
        threat_status = threat_monitor.is_monitoring if hasattr(threat_monitor, 'is_monitoring') else True
        
        return jsonify({
            'status': 'healthy',
            'timestamp': datetime.now().isoformat(),
            'database': 'connected',
            'threat_monitor': 'active' if threat_status else 'inactive',
            'active_scans': len(active_scans),
            'version': '2.0.0'
        })
    except Exception as e:
        return jsonify({
            'status': 'unhealthy',
            'timestamp': datetime.now().isoformat(),
            'error': str(e),
            'version': '2.0.0'
        }), 500

@app.route('/health/ready')
def readiness_check():
    """Readiness check for Kubernetes-style deployments"""
    try:
        # Check if all required services are ready
        with get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT COUNT(*) FROM users")
            cursor.fetchone()
            cursor.close()
            
        return jsonify({
            'status': 'ready',
            'timestamp': datetime.now().isoformat(),
            'database': 'ready',
            'services': 'ready'
        })
    except Exception as e:
        return jsonify({
            'status': 'not_ready',
            'timestamp': datetime.now().isoformat(),
            'error': str(e)
        }), 503

@app.route('/health/live')
def liveness_check():
    """Liveness check for basic application health"""
    return jsonify({
        'status': 'alive',
        'timestamp': datetime.now().isoformat(),
        'uptime': time.time() - app.start_time if hasattr(app, 'start_time') else 0
    })

# Memory cleanup function for scan results
def cleanup_old_scan_results():
    """Remove old scan results from memory to prevent memory leaks"""
    with results_lock:
        # Keep only last 100 scan results in memory
        if len(scan_results) > 100:
            # Get oldest scans by timestamp
            sorted_scans = sorted(scan_results.items(), 
                                key=lambda x: x[1].get('completed_at', ''), reverse=True)
            # Keep only the newest 50
            new_results = dict(sorted_scans[:50])
            scan_results.clear()
            scan_results.update(new_results)

def main():
    """Main application entry point"""
    try:
        # Set start time for uptime calculation
        app.start_time = time.time()
        
        # Initialize database tables
        init_database()
        
        print("InfoGather Web Dashboard starting...")
        print("Access the dashboard at: http://localhost:5001")
        
        port = int(os.environ.get('PORT', 5000))
        # Bind to all interfaces is intentional for containerized/cloud deployment
        app.run(host='0.0.0.0', port=port, debug=False, threaded=True)  # nosec B104
    except Exception as e:
        print(f"Failed to start application: {e}")
        cleanup()

if __name__ == '__main__':
    main()