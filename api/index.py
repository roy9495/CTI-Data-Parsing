import sys
import os

# Add project root directory to the python path so imports of ctihub work correctly on Vercel
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from ctihub.server import app
