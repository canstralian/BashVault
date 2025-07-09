
#!/usr/bin/env python3
"""
InfoGather Web Dashboard - Production Ready
Version 1.0.0
"""

import os
import logging
import sys
from datetime import datetime
from flask import Flask, request, jsonify
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from config import config
from security import add_security_headers, security_manager
from web_dashboard_simple import main as dashboard_main

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('logs/infogather.log'),
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger(__name__)

def create_app(config_name=None):
    """Application factory pattern"""
    if config_name is None:
        config_name = os.environ.get('FLASK_ENV', 'production')
    
    app = Flask(__name__)
    app.config.from_object(config[config_name])
    
    # Initialize configuration
    config[config_name].init_app(app)
    
    # Initialize rate limiter
    limiter = Limiter(
        app,
        key_func=get_remote_address,
        default_limits=["1000 per hour"]
    )
    
    # Security middleware
    @app.after_request
    def after_request(response):
        return add_security_headers(response)
    
    @app.before_request
    def before_request():
        # Check if IP is blocked
        if security_manager.is_blocked(request.remote_addr):
            return jsonify({'error': 'Access denied'}), 403
        
        # Log request
        logger.info(f"{request.method} {request.path} - {request.remote_addr}")
    
    # Error handlers
    @app.errorhandler(404)
    def not_found(error):
        return jsonify({'error': 'Resource not found'}), 404
    
    @app.errorhandler(500)
    def internal_error(error):
        logger.error(f"Internal server error: {str(error)}")
        return jsonify({'error': 'Internal server error'}), 500
    
    @app.errorhandler(429)
    def rate_limit_exceeded(error):
        return jsonify({'error': 'Rate limit exceeded'}), 429
    
    # Health check endpoints
    @app.route('/health')
    def health_check():
        """Health check endpoint"""
        return jsonify({
            'status': 'healthy',
            'timestamp': datetime.now().isoformat(),
            'version': '1.0.0'
        })
    
    @app.route('/health/ready')
    def readiness_check():
        """Readiness check endpoint"""
        # Check database connectivity
        try:
            from web_dashboard_simple import get_db_connection
            with get_db_connection() as conn:
                cursor = conn.cursor()
                cursor.execute("SELECT 1")
                cursor.fetchone()
                cursor.close()
            
            return jsonify({
                'status': 'ready',
                'timestamp': datetime.now().isoformat()
            })
        except Exception as e:
            logger.error(f"Readiness check failed: {str(e)}")
            return jsonify({
                'status': 'not_ready',
                'error': str(e)
            }), 503
    
    @app.route('/health/live')
    def liveness_check():
        """Liveness check endpoint"""
        return jsonify({
            'status': 'alive',
            'timestamp': datetime.now().isoformat()
        })
    
    # Import and register blueprints/routes
    from web_dashboard_simple import app as dashboard_app
    
    # Copy routes from dashboard app
    for rule in dashboard_app.url_map.iter_rules():
        if rule.endpoint != 'static':
            app.add_url_rule(
                rule.rule,
                rule.endpoint,
                dashboard_app.view_functions[rule.endpoint],
                methods=rule.methods
            )
    
    return app

if __name__ == '__main__':
    # Create logs directory
    os.makedirs('logs', exist_ok=True)
    
    # Create Flask app
    app = create_app()
    
    # Run application
    logger.info("Starting InfoGather Dashboard v1.0.0")
    logger.info("Access the dashboard at: http://0.0.0.0:5000")
    
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=False)
