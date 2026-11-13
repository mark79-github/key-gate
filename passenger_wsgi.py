import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# Passenger looks for a WSGI callable named "application".
from app import app as application
