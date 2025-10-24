# app.wsgi
import sys
import os

# Add your project directory to the Python path
project_home = '/home/yourusername/campus-skill-hub'
if project_home not in sys.path:
    sys.path.insert(0, project_home)

# Set environment variables
os.environ['PYTHONANYWHERE_SITE'] = 'true'

# Import your Flask app
from app import app as application
