#!/usr/bin/env python3
"""
BackupFinder One-Command Installer & Runner
Automatically installs Go (if needed) and runs BackupFinder tool
No manual cloning required - everything is automated!
"""

import os
import sys
import subprocess
import shutil
import tempfile
import argparse
from pathlib import Path

# Colors for terminal output
class Colors:
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    BOLD = '\033[1m'
    END = '\033[0m'

def print_banner():
    print(f"""
{Colors.CYAN}{Colors.BOLD}
╔══════════════════════════════════════════════════════════════╗
║                BackupFinder Auto-Setup v1.0                 ║
║          One-Command Installation & Execution Tool          ║
║                   Author: MuhammadWaseem                     ║
╚══════════════════════════════════════════════════════════════╝
{Colors.END}""")

def log(message, color=Colors.BLUE):
    print(f"{color}[*] {message}{Colors.END}")

def success(message):
    print(f"{Colors.GREEN}[+] {message}{Colors.END}")

def error(message):
    print(f"{Colors.RED}[-] {message}{Colors.END}")

def warning(message):
    print(f"{Colors.YELLOW}[!] {message}{Colors.END}")

def run_cmd(command, check=True, capture=True):
    """Execute shell command"""
    try:
        result = subprocess.run(command, shell=True, check=check, 
                              capture_output=capture, text=True)
        return result
    except subprocess.CalledProcessError:
        return None

def check_linux():
    """Ensure we're running on Linux"""
    if not sys.platform.startswith('linux'):
        error("This installer is designed for Linux systems only!")
        sys.exit(1)

def check_go_installed():
    """Check if Go is installed and return version"""
    log("Checking for Go installation...")
    result = run_cmd("go version", check=False)
    if result and result.returncode == 0:
        version = result.stdout.strip()
        success(f"Go found: {version}")
        return True
    warning("Go not found - will install automatically")
    return False

def install_go():
    """Install Go automatically"""
    log("Installing Go 1.22.3...")
    
    # Download and install Go
    commands = [
        "wget -q https://go.dev/dl/go1.22.3.linux-amd64.tar.gz",
        "sudo rm -rf /usr/local/go",
        "sudo tar -C /usr/local -xzf go1.22.3.linux-amd64.tar.gz",
        "rm -f go1.22.3.linux-amd64.tar.gz"
    ]
    
    for cmd in commands:
        if not run_cmd(cmd):
            error(f"Failed: {cmd}")
            return False
    
    # Setup PATH
    bashrc = Path.home() / ".bashrc"
    go_path = 'export PATH=$PATH:/usr/local/go/bin:$HOME/go/bin'
    
    # Add to bashrc if not exists
    if bashrc.exists():
        content = bashrc.read_text()
        if '/usr/local/go/bin' not in content:
            with open(bashrc, 'a') as f:
                f.write(f"\n# Go Path (BackupFinder installer)\n{go_path}\n")
    
    # Update current session
    os.environ['PATH'] = f"{os.environ.get('PATH', '')}:/usr/local/go/bin"
    
    success("Go installed successfully!")
    return True

def install_backupfinder():
    """Install BackupFinder using go install"""
    log("Installing BackupFinder...")
    
    # Set Go environment
    env = os.environ.copy()
    env['PATH'] = f"/usr/local/go/bin:{env.get('PATH', '')}"
    
    # Install BackupFinder
    result = subprocess.run(
        ["go", "install", "github.com/MuhammadWaseem29/BackupFinder/cmd/backupfinder@latest"],
        env=env, capture_output=True, text=True
    )
    
    if result.returncode == 0:
        success("BackupFinder installed successfully!")
        return True
    else:
        error("Failed to install BackupFinder")
        error(f"Error: {result.stderr}")
        return False

def run_backupfinder(args):
    """Run BackupFinder with provided arguments"""
    log("Running BackupFinder...")
    
    # Set environment
    env = os.environ.copy()
    env['PATH'] = f"/usr/local/go/bin:{Path.home()}/go/bin:{env.get('PATH', '')}"
    
    # Prepare command
    cmd = ["backupfinder"]
    if args:
        cmd.extend(args)
    else:
        cmd.append("--help")  # Show help if no args provided
    
    try:
        # Run BackupFinder directly
        subprocess.run(cmd, env=env, check=True)
        success("BackupFinder execution completed!")
    except subprocess.CalledProcessError as e:
        error(f"BackupFinder failed: {e}")
    except FileNotFoundError:
        error("BackupFinder not found in PATH")
        warning("Try running: source ~/.bashrc && backupfinder")

def main():
    # Parse arguments
    parser = argparse.ArgumentParser(description="BackupFinder One-Command Installer")
    parser.add_argument('--version', action='store_true', help='Show version')
    known_args, backupfinder_args = parser.parse_known_args()
    
    if known_args.version:
        print("BackupFinder Auto-Installer v1.0")
        return
    
    print_banner()
    
    # Check system
    check_linux()
    
    # Install Go if needed
    if not check_go_installed():
        if not install_go():
            error("Go installation failed!")
            sys.exit(1)
    
    # Install BackupFinder
    if not install_backupfinder():
        error("BackupFinder installation failed!")
        sys.exit(1)
    
    # Run BackupFinder
    run_backupfinder(backupfinder_args)
    
    # Show usage info
    if not backupfinder_args:
        print(f"""
{Colors.YELLOW}{Colors.BOLD}Quick Usage Examples:{Colors.END}
  {Colors.CYAN}python3 install_and_run.py -u example.com{Colors.END}
  {Colors.CYAN}python3 install_and_run.py -u example.com -w{Colors.END}
  {Colors.CYAN}python3 install_and_run.py -l targets.txt{Colors.END}

{Colors.GREEN}BackupFinder is now installed! You can also run directly:{Colors.END}
  {Colors.CYAN}backupfinder -u example.com{Colors.END}
        """)

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        warning("\nOperation cancelled by user")
        sys.exit(1)
    except Exception as e:
        error(f"Unexpected error: {e}")
        sys.exit(1)
