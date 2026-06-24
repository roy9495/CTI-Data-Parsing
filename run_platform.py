import os
import sys
import subprocess
import webbrowser
import time

def main():
    print("=" * 60)
    print("           STARTING CTIHUB PLATFORM")
    print("=" * 60)

    # Resolve paths to virtual env python and packages
    venv_dir = os.path.join(os.path.dirname(__file__), "venv")
    if sys.platform == "win32":
        python_exe = os.path.join(venv_dir, "Scripts", "python.exe")
        uvicorn_exe = os.path.join(venv_dir, "Scripts", "uvicorn.exe")
    else:
        python_exe = os.path.join(venv_dir, "bin", "python")
        uvicorn_exe = os.path.join(venv_dir, "bin", "uvicorn")

    if not os.path.exists(python_exe):
        print("[X] Virtual environment not found. Please create it first.")
        sys.exit(1)

    print("[*] Launching database initialization and API server...")

    # Parse port from command line arguments (defaults to 8000)
    port = "8000"
    for arg in sys.argv[1:]:
        if arg.startswith("--port="):
            port = arg.split("=")[1]
        elif arg.isdigit():
            port = arg

    # Commands list to run the server
    # We will invoke uvicorn as a module or direct script using the virtual environment python
    cmd = [python_exe, "-m", "uvicorn", "ctihub.server:app", "--host", "127.0.0.1", "--port", port, "--reload"]

    try:
        # Give a small delay and open the browser
        print(f"[OK] API Server starting at http://127.0.0.1:{port}/")
        print("[*] Press Ctrl+C in the terminal to stop the platform.")
        
        # Open web browser after a short delay
        def open_browser():
            time.sleep(2)
            print(f"[*] Opening CTIHub Dashboard in your default browser...")
            webbrowser.open(f"http://127.0.0.1:{port}/")

        import threading
        browser_thread = threading.Thread(target=open_browser)
        browser_thread.daemon = True
        browser_thread.start()

        # Run the server
        subprocess.run(cmd)

    except KeyboardInterrupt:
        print("\n[*] Shutting down CTIHub Platform. Goodbye!")
    except Exception as e:
        print(f"[X] Failed to run uvicorn server: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
