#!/usr/bin/env python3
"""
Database Models for InfoGather Web Dashboard
SQLAlchemy models for PostgreSQL database
"""

from flask_sqlalchemy import SQLAlchemy
from datetime import datetime
import json

db = SQLAlchemy()

def init_db(app):
    """Initialize database with Flask app"""
    db.init_app(app)
    with app.app_context():
        db.create_all()

class User(db.Model):
    __tablename__ = 'users'

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=True)
    password_hash = db.Column(db.String(255), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    last_login = db.Column(db.DateTime, nullable=True)
    is_active = db.Column(db.Boolean, default=True)
    role = db.Column(db.String(20), default='user')

    # Relationships
    scans = db.relationship('Scan', backref='user', lazy=True, cascade='all, delete-orphan')

class Scan(db.Model):
    __tablename__ = 'scans'

    id = db.Column(db.String(36), primary_key=True)
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

    # Relationships
    results = db.relationship('ScanResult', backref='scan', lazy=True, cascade='all, delete-orphan')
    findings = db.relationship('Finding', backref='scan', lazy=True, cascade='all, delete-orphan')
    summary = db.relationship('ScanSummary', backref='scan', uselist=False, cascade='all, delete-orphan')

    @property
    def modules_list(self):
        """Get modules as list"""
        try:
            return json.loads(self.modules) if self.modules else []
        except:
            return []

    @modules_list.setter
    def modules_list(self, value):
        """Set modules from list"""
        self.modules = json.dumps(value) if value else '[]'

class ScanResult(db.Model):
    __tablename__ = 'scan_results'

    id = db.Column(db.Integer, primary_key=True)
    scan_id = db.Column(db.String(36), db.ForeignKey('scans.id'), nullable=False)
    module_name = db.Column(db.String(50), nullable=False)
    results = db.Column(db.Text, nullable=False)  # JSON string
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    @property
    def data(self):
        """Get results as dict"""
        try:
            return json.loads(self.results) if self.results else {}
        except:
            return {}

    @data.setter
    def data(self, value):
        """Set results from dict"""
        self.results = json.dumps(value) if value else '{}'

class Finding(db.Model):
    __tablename__ = 'findings'

    id = db.Column(db.Integer, primary_key=True)
    scan_id = db.Column(db.String(36), db.ForeignKey('scans.id'), nullable=False)
    module = db.Column(db.String(50), nullable=False)
    severity = db.Column(db.String(20), nullable=False)
    title = db.Column(db.String(255), nullable=False)
    description = db.Column(db.Text, nullable=True)
    evidence = db.Column(db.Text, nullable=True)
    remediation = db.Column(db.Text, nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class ScanSummary(db.Model):
    __tablename__ = 'scan_summaries'

    id = db.Column(db.Integer, primary_key=True)
    scan_id = db.Column(db.String(36), db.ForeignKey('scans.id'), nullable=False)
    total_findings = db.Column(db.Integer, default=0)
    critical_findings = db.Column(db.Integer, default=0)
    high_findings = db.Column(db.Integer, default=0)
    medium_findings = db.Column(db.Integer, default=0)
    low_findings = db.Column(db.Integer, default=0)
    ports_found = db.Column(db.Integer, default=0)
    subdomains_found = db.Column(db.Integer, default=0)
    vulnerabilities_found = db.Column(db.Integer, default=0)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class AuditLog(db.Model):
    __tablename__ = 'audit_logs'

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=True)
    action = db.Column(db.String(100), nullable=False)
    resource = db.Column(db.String(100), nullable=True)
    details = db.Column(db.Text, nullable=True)
    ip_address = db.Column(db.String(45), nullable=True)
    user_agent = db.Column(db.Text, nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)