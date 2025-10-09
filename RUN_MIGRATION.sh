#!/bin/bash

# Script to run database migration for saved device lists and commands feature
# This script activates the virtual environment and runs the migration

echo "========================================="
echo "Saved Device Lists & Commands Migration"
echo "========================================="
echo ""

# Check if venv exists
if [ ! -d "../venv" ]; then
    echo "❌ Virtual environment not found!"
    echo "Please create it first with: python3 -m venv venv"
    exit 1
fi

echo "✓ Virtual environment found"
echo ""

# Activate virtual environment
echo "Activating virtual environment..."
source ../venv/bin/activate

# Check if Flask is installed
if ! python -c "import flask" 2>/dev/null; then
    echo "❌ Flask not installed in virtual environment!"
    echo "Please install dependencies with: pip install -r requirements.txt"
    deactivate
    exit 1
fi

echo "✓ Flask installed"
echo ""

# Run migration
echo "Running database migration..."
echo ""
flask db upgrade

if [ $? -eq 0 ]; then
    echo ""
    echo "========================================="
    echo "✅ Migration completed successfully!"
    echo "========================================="
    echo ""
    echo "New tables created:"
    echo "  - saved_device_lists"
    echo "  - saved_commands"
    echo ""
    echo "You can now access the features at:"
    echo "  - /saved-items/device-lists"
    echo "  - /saved-items/commands"
    echo ""
else
    echo ""
    echo "========================================="
    echo "❌ Migration failed!"
    echo "========================================="
    echo ""
    echo "Please check the error messages above"
    deactivate
    exit 1
fi

deactivate
