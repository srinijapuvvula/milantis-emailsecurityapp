#!/bin/bash
# Install system dependencies
apt-get update
apt-get install -y wkhtmltopdf

# Start the application
gunicorn --bind=0.0.0.0 --timeout 600 app:app