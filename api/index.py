import sys
import os

# Add project root directory to the python path so imports of ctihub work correctly on Vercel
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.append(os.getcwd())

from ctihub.server import app as _app

# Assign to top-level 'app' variable for Vercel's static AST parser
app = _app


