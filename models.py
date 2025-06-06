"""
Database Models for InfoGather Web Dashboard
PostgreSQL database models using SQLAlchemy
"""

from flask_sqlalchemy import SQLAlchemy
from datetime import datetime
import json

db = SQLAlchemy()

class User(db.Model):
    """User model for authentication"""
    __tablename__ = 'users'
    
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    last_login = db.Column(db.DateTime, nullable=True)
    is_active = db.Column(db.Boolean, default=True)
    
    # Relationship with scans
    scans = db.relationship('Scan', backref='user', lazy=True, cascade='all, delete-orphan')
    
    def __repr__(self):
        return f'<User {self.username}>'

class Scan(db.Model):
    """Scan model for storing scan information"""
    __tablename__ = 'scans'
    
    id = db.Column(db.String(36), primary_key=True)  # UUID
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    target = db.Column(db.String(255), nullable=False)
    ports = db.Column(db.String(100), nullable=True)
    modules = db.Column(db.Text, nullable=False)  # JSON string
    status = db.Column(db.String(20), default='pending')
    started_at = db.Column(db.DateTime, default=datetime.utcnow)
    completed_at = db.Column(db.DateTime, nullable=True)
    progress = db.Column(db.Integer, default=0)
    current_module = db.Column(db.String(50), nullable=True)
    error_message = db.Column(db.Text, nullable=True)
    
    # Relationship with results
    results = db.relationship('ScanResult', backref='scan', lazy=True, cascade='all, delete-orphan')
    
    @property
    def modules_list(self):
        """Get modules as a list"""
        try:
            return json.loads(self.modules)
        except (json.JSONDecodeError, TypeError):
            return []
    
    @modules_list.setter
    def modules_list(self, value):
        """Set modules from a list"""
        self.modules = json.dumps(value)
    
    @property
    def duration(self):
        """Calculate scan duration"""
        if self.started_at and self.completed_at:
            return self.completed_at - self.started_at
        return None
    
    def __repr__(self):
        return f'<Scan {self.id}: {self.target}>'

class ScanResult(db.Model):
    """Scan results model for storing detailed findings"""
    __tablename__ = 'scan_results'
    
    id = db.Column(db.Integer, primary_key=True)
    scan_id = db.Column(db.String(36), db.ForeignKey('scans.id'), nullable=False)
    module_name = db.Column(db.String(50), nullable=False)
    result_data = db.Column(db.Text, nullable=False)  # JSON string
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    @property
    def data(self):
        """Get result data as dictionary"""
        try:
            return json.loads(self.result_data)
        except (json.JSONDecodeError, TypeError):
            return {}
    
    @data.setter
    def data(self, value):
        """Set result data from dictionary"""
        self.result_data = json.dumps(value, indent=2)
    
    def __repr__(self):
        return f'<ScanResult {self.id}: {self.module_name}>'

class Finding(db.Model):
    """Security findings model"""
    __tablename__ = 'findings'
    
    id = db.Column(db.Integer, primary_key=True)
    scan_id = db.Column(db.String(36), db.ForeignKey('scans.id'), nullable=False)
    module_name = db.Column(db.String(50), nullable=False)
    finding_type = db.Column(db.String(100), nullable=False)
    severity = db.Column(db.String(20), nullable=False)  # critical, high, medium, low
    title = db.Column(db.String(255), nullable=False)
    description = db.Column(db.Text, nullable=True)
    evidence = db.Column(db.Text, nullable=True)
    remediation = db.Column(db.Text, nullable=True)
    cvss_score = db.Column(db.Float, nullable=True)
    cve_id = db.Column(db.String(20), nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    # Add index for faster queries
    __table_args__ = (
        db.Index('idx_scan_severity', 'scan_id', 'severity'),
        db.Index('idx_finding_type', 'finding_type'),
    )
    
    def __repr__(self):
        return f'<Finding {self.id}: {self.title}>'

class ScanSummary(db.Model):
    """Scan summary statistics"""
    __tablename__ = 'scan_summaries'
    
    id = db.Column(db.Integer, primary_key=True)
    scan_id = db.Column(db.String(36), db.ForeignKey('scans.id'), nullable=False, unique=True)
    total_findings = db.Column(db.Integer, default=0)
    critical_findings = db.Column(db.Integer, default=0)
    high_findings = db.Column(db.Integer, default=0)
    medium_findings = db.Column(db.Integer, default=0)
    low_findings = db.Column(db.Integer, default=0)
    ports_found = db.Column(db.Integer, default=0)
    subdomains_found = db.Column(db.Integer, default=0)
    vulnerabilities_found = db.Column(db.Integer, default=0)
    cloud_assets_found = db.Column(db.Integer, default=0)
    social_intel_found = db.Column(db.Integer, default=0)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    def __repr__(self):
        return f'<ScanSummary {self.scan_id}: {self.total_findings} findings>'

class AuditLog(db.Model):
    """Audit log for tracking user actions"""
    __tablename__ = 'audit_logs'
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    action = db.Column(db.String(100), nullable=False)
    resource_type = db.Column(db.String(50), nullable=True)
    resource_id = db.Column(db.String(36), nullable=True)
    details = db.Column(db.Text, nullable=True)
    ip_address = db.Column(db.String(45), nullable=True)
    user_agent = db.Column(db.Text, nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    # Add index for faster queries
    __table_args__ = (
        db.Index('idx_user_action', 'user_id', 'action'),
        db.Index('idx_created_at', 'created_at'),
    )
    
    def __repr__(self):
        return f'<AuditLog {self.id}: {self.action}>'

def init_db(app):
    """Initialize database with app context"""
    db.init_app(app)
    
    with app.app_context():
        # Create all tables
        db.create_all()
        
        # Create default admin user if it doesn't exist
        admin_user = User.query.filter_by(username='admin').first()
        if not admin_user:
            from werkzeug.security import generate_password_hash
            admin_user = User(
                username='admin',
                password_hash=generate_password_hash('admin123'),
                email='admin@infogather.local',
                is_active=True
            )
            db.session.add(admin_user)
            db.session.commit()
            print("Created default admin user: admin / admin123")