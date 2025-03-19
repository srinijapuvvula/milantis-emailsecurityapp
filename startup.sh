#!/bin/bash
set -e  # Exit immediately if a command exits with a non-zero status

echo "Starting deployment script..."

# Install system dependencies
echo "Updating package lists..."
apt-get update

echo "Installing wkhtmltopdf and dependencies..."
apt-get install -y wkhtmltopdf xvfb fontconfig libxrender1 libjpeg-turbo8

# Verify wkhtmltopdf installation
if ! command -v wkhtmltopdf &> /dev/null; then
    echo "ERROR: wkhtmltopdf installation failed!"
    
    # Alternative installation method
    echo "Trying alternative installation method..."
    wget https://github.com/wkhtmltopdf/packaging/releases/download/0.12.6-1/wkhtmltox_0.12.6-1.focal_amd64.deb
    apt-get install -y ./wkhtmltox_0.12.6-1.focal_amd64.deb
    
    # Create symbolic link if installed to non-standard location
    if [ -f /usr/local/bin/wkhtmltopdf ] && [ ! -f /usr/bin/wkhtmltopdf ]; then
        ln -s /usr/local/bin/wkhtmltopdf /usr/bin/wkhtmltopdf
    fi
    
    # Verify installation again
    if ! command -v wkhtmltopdf &> /dev/null; then
        echo "ERROR: wkhtmltopdf installation failed after alternative method. Continuing anyway..."
    else
        echo "wkhtmltopdf installed successfully with alternative method!"
    fi
else
    echo "wkhtmltopdf installed successfully!"
fi

# Print wkhtmltopdf version and location for debugging
echo "wkhtmltopdf version:"
wkhtmltopdf --version
echo "wkhtmltopdf location:"
which wkhtmltopdf

# Start the application
echo "Starting the application..."
gunicorn --bind=0.0.0.0 --timeout 600 app:app