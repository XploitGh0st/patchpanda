#!/usr/bin/env python3
"""
Local Test Script for Patch Panda Security Scanner
This script allows you to test the scanner locally without GitHub Actions
"""

import os
import sys

# Add the current directory to Python path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# Import the scan module
from scan import analyze_code_with_gemini

def test_single_file(file_path, api_key):
    """Test the scanner on a single file"""
    print(f"🧪 Testing Patch Panda on: {file_path}")
    
    # Set environment variable
    os.environ['GEMINI_API_KEY'] = api_key
    
    try:
        # Read the file
        with open(file_path, 'r', encoding='utf-8') as f:
            content = f.read()
        
        print(f"📄 File size: {len(content)} characters")
        print("🔍 Analyzing with Gemini...")
        
        # Analyze the file
        result = analyze_code_with_gemini(content, file_path)
        
        print("\n" + "="*60)
        print("🛡️ SCAN RESULTS")
        print("="*60)
        print(result)
        print("="*60)
        
        if "No issues found." in result:
            print("✅ No vulnerabilities detected")
        elif result.startswith("Error"):
            print("❌ Analysis failed")
        else:
            print("🚨 Vulnerabilities detected!")
            
    except FileNotFoundError:
        print(f"❌ Error: File '{file_path}' not found")
    except Exception as e:
        print(f"❌ Error: {e}")

def main():
    print("🐼 Patch Panda Local Test Script")
    print("=" * 40)
    
    # Check for API key
    api_key = os.getenv('GEMINI_API_KEY')
    if not api_key:
        api_key = input("Enter your Gemini API key: ").strip()
        if not api_key:
            print("❌ API key is required")
            sys.exit(1)
    
    # Get file to test
    if len(sys.argv) > 1:
        file_path = sys.argv[1]
    else:
        file_path = input("Enter path to file to test: ").strip()
        if not file_path:
            print("❌ File path is required")
            sys.exit(1)
    
    # Test the file
    test_single_file(file_path, api_key)

if __name__ == "__main__":
    main()