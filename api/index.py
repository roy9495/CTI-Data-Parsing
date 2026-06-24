import sys
import os
import traceback

# Add project root directory to the python path so imports of ctihub work correctly on Vercel
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.append(os.getcwd())

app = None
import_error_message = None

try:
    from ctihub.server import app as _app
    app = _app
except Exception as e:
    import_error_message = traceback.format_exc()
    # Also log it to stderr
    print("!!! CRITICAL IMPORT EXCEPTION !!!", file=sys.stderr)
    traceback.print_exc(file=sys.stderr)

# Fallback app to render traceback if import failed
if import_error_message or app is None:
    from fastapi import FastAPI
    from fastapi.responses import HTMLResponse

    app = FastAPI()

    @app.get("/{path:path}")
    def debug_error(path: str):
        html_content = f"""
        <html>
            <head><title>CTIHub Debugger</title></head>
            <body style="font-family: monospace; padding: 20px; background: #1a1a1a; color: #ff5555; line-height: 1.5;">
                <h1 style="color: #ff3333; border-bottom: 1px solid #ff3333; padding-bottom: 10px;">Critical Import/Compile Error</h1>
                <p>The Python application failed to import. Below is the stack trace:</p>
                <pre style="background: #2a2a2a; padding: 15px; border-radius: 5px; overflow-x: auto; color: #f8f8f2;">{import_error_message or 'Failed to load FastAPI app instance.'}</pre>
            </body>
        </html>
        """
        return HTMLResponse(content=html_content, status_code=500)
