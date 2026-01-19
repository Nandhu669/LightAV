#!/usr/bin/env python3
"""
LightAV - Lightweight Antivirus Application

This is the main entry point for running LightAV.
It provides options to run in different modes:
  - GUI mode (default)
  - Agent/background mode
  - Service mode
"""

import sys
import argparse


def main():
    parser = argparse.ArgumentParser(
        description="LightAV - Lightweight Antivirus Application",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python run_lightav.py          # Run GUI (default)
  python run_lightav.py --gui    # Run GUI explicitly
  python run_lightav.py --agent  # Run background agent
  python run_lightav.py --scan <path>  # Scan a specific file/folder
        """
    )
    
    parser.add_argument(
        "--gui", 
        action="store_true", 
        help="Launch the graphical user interface (default)"
    )
    parser.add_argument(
        "--agent", 
        action="store_true", 
        help="Run the background monitoring agent"
    )
    parser.add_argument(
        "--scan", 
        type=str, 
        metavar="PATH",
        help="Scan a specific file or directory"
    )
    
    args = parser.parse_args()
    
    # Default to GUI mode if no arguments provided
    if not any([args.gui, args.agent, args.scan]):
        args.gui = True
    
    if args.scan:
        from agent.scanner import process_file
        import os
        
        target = args.scan
        if os.path.isfile(target):
            result = process_file(target)
            print(f"Scan result: {result}")
        elif os.path.isdir(target):
            for root, dirs, files in os.walk(target):
                for file in files:
                    filepath = os.path.join(root, file)
                    try:
                        result = process_file(filepath)
                        print(f"{filepath}: {result}")
                    except Exception as e:
                        print(f"{filepath}: Error - {e}")
        else:
            print(f"Error: Path not found: {target}")
            sys.exit(1)
    
    elif args.agent:
        from agent.main_agent import main_loop
        print("[LightAV] Starting background agent...")
        main_loop()
    
    elif args.gui:
        from gui.main_window import main
        print("[LightAV] Launching GUI...")
        main()


if __name__ == "__main__":
    main()
