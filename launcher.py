import sys
import subprocess
import os
import importlib.metadata

REQUIRED_FILES = ['requirements.txt', 'app.py']

def check_files():
    """Check if necessary files exist."""
    missing = []
    for f in REQUIRED_FILES:
        if not os.path.exists(f):
            missing.append(f)
    return missing

def get_missing_requirements():
    """Check for missing requirements from requirements.txt."""
    if not os.path.exists('requirements.txt'):
        return []
    
    with open('requirements.txt', 'r') as f:
        requirements = [
            line.strip() 
            for line in f 
            if line.strip() and not line.startswith('#')
        ]
    
    missing = []
    installed = {dist.metadata['Name'].lower() for dist in importlib.metadata.distributions()}
    
    for req in requirements:
        # Handle version specifiers if present, for now simple check
        req_name = req.split('==')[0].split('>=')[0].split('<')[0].strip().lower()
        
        # Normalize name (replace - with _)
        req_name_norm = req_name.replace('-', '_')
        
        # Check against installed packages (checking both raw and normalized)
        if req_name not in installed and req_name_norm not in installed:
             # mimic pip freeze name often uses underscores or different casing
             # But importlib usually normalizes to hyphens or underscores depending on version
             # Let's try to be robust by checking variations
             found = False
             for inst in installed:
                 if inst.replace('-', '_') == req_name_norm:
                     found = True
                     break
             if not found:
                 missing.append(req)
                 
    return missing

def install_requirements(missing_reqs):
    """Install missing requirements using pip."""
    print(f"Installing {len(missing_reqs)} missing packages...")
    try:
        subprocess.check_call([sys.executable, "-m", "pip", "install", *missing_reqs])
        print("Installation complete.")
        return True
    except subprocess.CalledProcessError as e:
        print(f"Error installing packages: {e}")
        return False

def main():
    print("--- Cybermon Launcher ---")
    print("Checking environment...")

    # 1. Check Files
    missing_files = check_files()
    if missing_files:
        print(f"CRITICAL ERROR: Missing core files: {', '.join(missing_files)}")
        print("Please ensure you are running this from the application directory.")
        sys.exit(1)

    # 2. Check Requirements
    missing_reqs = get_missing_requirements()
    
    if missing_reqs:
        print(f"WARNING: Found {len(missing_reqs)} missing dependencies:")
        for req in missing_reqs:
            print(f" - {req}")
        
        while True:
            choice = input("\nDo you want to run auto-install for these packages? (y/n): ").strip().lower()
            if choice == 'y':
                if install_requirements(missing_reqs):
                    print("Dependencies installed successfully.")
                    break
                else:
                    print("Failed to install dependencies. Please verify your internet connection or install manually.")
                    sys.exit(1)
            elif choice == 'n':
                print("Cannot proceed without dependencies. Exiting.")
                sys.exit(1)
            else:
                print("Invalid input. Please enter 'y' or 'n'.")
    else:
        print("Environment check: OK")

    # 3. Launch App
    print("\nStarting Cybermon...")
    print("---------------------")
    try:
        # Run app.py in a subprocess
        subprocess.run([sys.executable, 'app.py'])
    except KeyboardInterrupt:
        print("\nCybermon stopped.")

if __name__ == '__main__':
    main()
