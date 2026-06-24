import sys
import os

# Add project root directory to the python path so imports of ctihub work correctly on Vercel
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.append(os.getcwd())

try:
    from ctihub.server import app
except Exception as e:
    import traceback
    print("!!! CRITICAL EXCEPTION DURING API IMPORT !!!", file=sys.stderr)
    traceback.print_exc(file=sys.stderr)
    raise e

