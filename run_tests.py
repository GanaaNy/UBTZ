#!/usr/bin/env python
"""
Simple test runner script for login tests
Usage: python run_tests.py
"""
import sys
import subprocess

if __name__ == '__main__':
    # Run pytest with verbose output
    result = subprocess.run(
        [sys.executable, '-m', 'pytest', 'test_login.py', '-v', '--tb=short'],
        cwd='.'
    )
    sys.exit(result.returncode)

