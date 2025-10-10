#!/bin/bash
# Database Synchronization Wrapper Script

echo "=============================================="
echo "NetOps Tools - Database Sync"
echo "=============================================="
echo ""

# Check if venv exists
if [ ! -d "venv" ]; then
    echo "❌ Virtual environment not found!"
    echo "Please create it first with: python3 -m venv venv"
    exit 1
fi

echo "✓ Activating virtual environment..."
source venv/bin/activate

# Check if Flask is installed
if ! python -c "import flask" 2>/dev/null; then
    echo "❌ Flask not installed in virtual environment!"
    echo "Please install dependencies with: pip install -r requirements.txt"
    deactivate
    exit 1
fi

echo "✓ Dependencies installed"
echo ""

# Run sync script
python sync_database.py

exit_code=$?

deactivate

exit $exit_code
