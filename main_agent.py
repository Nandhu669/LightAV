#!/usr/bin/env python3
"""
LightAV Main Agent Entry Point

This module serves as the root-level entry point for the LightAV agent.
It imports and runs the main agent loop from the agent package.
"""

from agent.main_agent import main_loop

if __name__ == "__main__":
    main_loop()
