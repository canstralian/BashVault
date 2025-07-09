#!/bin/bash

# InfoGather - Quick Setup Script
# This script sets up the development environment

set -e

echo "🚀 Setting up InfoGather development environment..."

# Create directories
echo "📁 Creating necessary directories..."
mkdir -p logs reports backups scripts .github/workflows

# Copy environment template
echo "⚙️  Setting up environment configuration..."
if [ ! -f .env ]; then
    cp .env.example .env
    echo "✅ Created .env file from template"
    echo "🔧 Please edit .env with your configuration"
else
    echo "✅ .env file already exists"
fi

# Install Python dependencies
echo "📦 Installing Python dependencies..."
python -m pip install --upgrade pip
pip install -r requirements.txt || echo "⚠️  Some dependencies may need manual installation"

# Install development dependencies
echo "🔧 Installing development dependencies..."
pip install pytest pytest-cov pytest-flask black flake8 mypy bandit safety

# Initialize database
echo "🗄️  Initializing database..."
python -c "from web_dashboard_simple import init_database; init_database()" || echo "⚠️  Database initialization may need manual setup"

# Set up Git hooks (if in git repo)
if [ -d .git ]; then
    echo "🔗 Setting up Git hooks..."
    # Create pre-commit hook
    cat > .git/hooks/pre-commit << 'EOF'
#!/bin/bash
# Run code quality checks before commit
echo "Running code quality checks..."
black --check . || exit 1
flake8 . || exit 1
echo "All checks passed!"
EOF
    chmod +x .git/hooks/pre-commit
    echo "✅ Git hooks configured"
fi

# Create startup script
echo "🚀 Creating startup script..."
cat > scripts/start.sh << 'EOF'
#!/bin/bash
echo "Starting InfoGather Web Dashboard..."
python web_dashboard_simple.py
EOF
chmod +x scripts/start.sh

# Create testing script
echo "🧪 Creating testing script..."
cat > scripts/test.sh << 'EOF'
#!/bin/bash
echo "Running InfoGather tests..."
pytest tests/ -v --tb=short
EOF
chmod +x scripts/test.sh

echo "✅ Setup completed successfully!"
echo ""
echo "🎉 InfoGather is ready to use!"
echo ""
echo "📝 Next steps:"
echo "1. Edit .env file with your configuration"
echo "2. Run: ./scripts/start.sh"
echo "3. Open: http://localhost:5001"
echo ""
echo "🔧 Available commands:"
echo "  ./scripts/start.sh  - Start the web dashboard"
echo "  ./scripts/test.sh   - Run tests"
echo "  ./deploy.sh         - Production deployment"
echo ""
echo "📖 Documentation:"
echo "  README.md          - Complete documentation"
echo "  CONTRIBUTING.md    - How to contribute"
echo "  CHANGELOG.md       - Version history"