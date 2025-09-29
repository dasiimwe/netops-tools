#!/usr/bin/env python3
import os
import sys
from app import create_app
from app.models import db

# Get configuration from environment
config_name = os.getenv('FLASK_ENV', 'development')

# Create the Flask application
app = create_app(config_name)

if __name__ == '__main__':
    # Check if running in debug mode
    debug = config_name == 'development'
    
    # Run the application
    app.run(
        host='0.0.0.0',
        port=5001,
        debug=debug
    )