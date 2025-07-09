#!/bin/bash

# InfoGather - Production Deployment Script
# This script handles production deployment with health checks and rollback capabilities

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Configuration
APP_NAME="infogather"
HEALTH_CHECK_URL="http://localhost:5000/health"
BACKUP_DIR="backups"
DEPLOY_TIMEOUT=300

echo_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

echo_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

echo_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Check prerequisites
check_prerequisites() {
    echo_info "Checking prerequisites..."
    
    # Check if Docker is installed
    if ! command -v docker &> /dev/null; then
        echo_error "Docker is not installed. Please install Docker first."
        exit 1
    fi
    
    # Check if Docker Compose is installed
    if ! command -v docker-compose &> /dev/null; then
        echo_error "Docker Compose is not installed. Please install Docker Compose first."
        exit 1
    fi
    
    # Check if PostgreSQL client is available
    if ! command -v psql &> /dev/null; then
        echo_warn "PostgreSQL client not found. Database operations may be limited."
    fi
    
    echo_info "Prerequisites check completed."
}

# Create backup
create_backup() {
    echo_info "Creating backup..."
    
    mkdir -p "$BACKUP_DIR"
    
    # Create backup with timestamp
    BACKUP_FILE="$BACKUP_DIR/backup_$(date +%Y%m%d_%H%M%S).tar.gz"
    
    # Backup database if running
    if docker-compose ps db | grep -q "Up"; then
        echo_info "Backing up database..."
        docker-compose exec db pg_dump -U infogather infogather > "$BACKUP_DIR/db_backup_$(date +%Y%m%d_%H%M%S).sql"
    fi
    
    # Backup application files
    tar -czf "$BACKUP_FILE" \
        --exclude='__pycache__' \
        --exclude='*.pyc' \
        --exclude='.git' \
        --exclude='venv' \
        --exclude='logs' \
        --exclude='backups' \
        .
    
    echo_info "Backup created: $BACKUP_FILE"
}

# Run tests
run_tests() {
    echo_info "Running tests..."
    
    # Install test dependencies
    pip install pytest pytest-cov pytest-flask black flake8 mypy bandit safety
    
    # Run code quality checks
    echo_info "Running code quality checks..."
    black --check . || (echo_error "Code formatting check failed" && exit 1)
    flake8 . || (echo_error "Linting failed" && exit 1)
    mypy . --ignore-missing-imports || echo_warn "Type checking completed with warnings"
    
    # Run security checks
    echo_info "Running security checks..."
    bandit -r . -x tests/ || echo_warn "Security scan completed with warnings"
    safety check || echo_warn "Dependency check completed with warnings"
    
    # Run unit tests
    echo_info "Running unit tests..."
    pytest tests/ -v --tb=short || (echo_error "Tests failed" && exit 1)
    
    echo_info "All tests passed!"
}

# Deploy application
deploy_application() {
    echo_info "Deploying application..."
    
    # Stop existing containers
    docker-compose down
    
    # Build and start containers
    docker-compose up -d --build
    
    # Wait for application to be ready
    echo_info "Waiting for application to be ready..."
    for i in {1..30}; do
        if curl -f "$HEALTH_CHECK_URL" &>/dev/null; then
            echo_info "Application is ready!"
            break
        fi
        echo "Waiting... ($i/30)"
        sleep 10
    done
    
    # Final health check
    if ! curl -f "$HEALTH_CHECK_URL" &>/dev/null; then
        echo_error "Application health check failed after deployment"
        echo_error "Rolling back..."
        docker-compose down
        exit 1
    fi
    
    echo_info "Deployment completed successfully!"
}

# Health check
health_check() {
    echo_info "Performing health check..."
    
    # Check application health
    if curl -f "$HEALTH_CHECK_URL" &>/dev/null; then
        echo_info "Application is healthy"
    else
        echo_error "Application health check failed"
        return 1
    fi
    
    # Check database connectivity
    if docker-compose exec db psql -U infogather -d infogather -c "SELECT 1;" &>/dev/null; then
        echo_info "Database is healthy"
    else
        echo_error "Database health check failed"
        return 1
    fi
    
    echo_info "All health checks passed!"
}

# Show deployment status
show_status() {
    echo_info "Deployment Status:"
    echo
    docker-compose ps
    echo
    echo_info "Application URLs:"
    echo "  - Web Dashboard: http://localhost:5000"
    echo "  - Health Check: http://localhost:5000/health"
    echo "  - Readiness Check: http://localhost:5000/health/ready"
    echo "  - Liveness Check: http://localhost:5000/health/live"
    echo
    echo_info "Logs:"
    echo "  - Application: docker-compose logs app"
    echo "  - Database: docker-compose logs db"
    echo "  - All services: docker-compose logs"
}

# Main deployment function
main() {
    echo_info "Starting InfoGather deployment..."
    
    case "${1:-deploy}" in
        "deploy")
            check_prerequisites
            create_backup
            run_tests
            deploy_application
            health_check
            show_status
            ;;
        "test")
            run_tests
            ;;
        "backup")
            create_backup
            ;;
        "health")
            health_check
            ;;
        "status")
            show_status
            ;;
        "rollback")
            echo_info "Rolling back deployment..."
            docker-compose down
            echo_info "Rollback completed. Please restore from backup if needed."
            ;;
        *)
            echo "Usage: $0 {deploy|test|backup|health|status|rollback}"
            echo
            echo "Commands:"
            echo "  deploy   - Full deployment with tests and health checks"
            echo "  test     - Run tests only"
            echo "  backup   - Create backup only"
            echo "  health   - Run health checks only"
            echo "  status   - Show deployment status"
            echo "  rollback - Rollback deployment"
            exit 1
            ;;
    esac
}

# Run main function
main "$@"