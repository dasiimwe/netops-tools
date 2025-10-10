#!/bin/bash
# Production startup script for netops-tools

echo "=============================================="
echo "Starting NetOps Tools - Production Mode"
echo "=============================================="
echo ""

# Check if virtual environment exists
if [ ! -d "venv" ]; then
    echo "❌ Virtual environment not found!"
    echo "Please create it first with: python3 -m venv venv"
    exit 1
fi

# Activate virtual environment
echo "✓ Activating virtual environment..."
source venv/bin/activate

# Check if .env exists
if [ ! -f ".env" ]; then
    echo "⚠️  Warning: .env file not found!"
    echo "Please create .env file with production settings"
    echo "See DEPLOYMENT.md for details"
    exit 1
fi

# Load environment variables
export $(grep -v '^#' .env | xargs)

# Check if Gunicorn is installed
if ! python -c "import gunicorn" 2>/dev/null; then
    echo "❌ Gunicorn not installed!"
    echo "Installing dependencies..."
    pip install -r requirements.txt
fi

echo "✓ Environment configured"
echo ""

# Create logs directory if it doesn't exist
mkdir -p logs

# Display configuration
echo "Configuration:"
echo "  Workers: ${GUNICORN_WORKERS:-4}"
echo "  Bind: ${GUNICORN_BIND:-127.0.0.1:5000}"
echo "  Timeout: ${GUNICORN_TIMEOUT:-300}s"
echo ""

# Start Gunicorn
echo "Starting Gunicorn server..."
echo "=============================================="
echo ""

# Use config file if it exists, otherwise use environment variables
if [ -f "gunicorn_config.py" ]; then
    exec gunicorn -c gunicorn_config.py run:app
else
    exec gunicorn \
        --workers ${GUNICORN_WORKERS:-4} \
        --bind ${GUNICORN_BIND:-127.0.0.1:5000} \
        --timeout ${GUNICORN_TIMEOUT:-300} \
        --access-logfile logs/access.log \
        --error-logfile logs/error.log \
        --log-level ${GUNICORN_LOG_LEVEL:-info} \
        --capture-output \
        run:app
fi
