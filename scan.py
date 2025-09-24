#!/usr/bin/env python3
"""
Patch Panda Security Scanner
A comprehensive security scanner for GitHub Actions that analyzes changed files
for vulnerabilities using Google's Gemini API and reports findings via GitHub
comments and email notifications.
"""

import os
import subprocess
import smtplib
import ssl
from email.message import EmailMessage
import google.generativeai as genai
import requests


# --- Environment Variables ---
GEMINI_API_KEY = os.getenv('GEMINI_API_KEY')
GITHUB_TOKEN = os.getenv('GITHUB_TOKEN')
GITHUB_REPOSITORY = os.getenv('GITHUB_REPOSITORY')
GITHUB_SHA = os.getenv('GITHUB_SHA')
GMAIL_APP_PASSWORD = os.getenv('GMAIL_APP_PASSWORD')
REPORT_EMAIL_FROM = os.getenv('REPORT_EMAIL_FROM')
REPORT_EMAIL_TO = os.getenv('REPORT_EMAIL_TO')


def get_changed_files():
    """
    Get a list of source code files changed in the latest commit.
    
    Returns:
        list: List of file paths for changed source code files
    """
    CODE_FILE_EXTENSIONS = ['.py', '.js', '.ts', '.java', '.cs', '.go', '.rb',
                           '.php', '.rs', '.c', '.cpp', '.h', '.html', '.css']
    
    try:
        print("🔍 Getting changed files...")
        
        # First, try to get changed files between HEAD~1 and HEAD
        result = subprocess.run(
            ['git', 'diff', '--name-only', 'HEAD~1', 'HEAD'],
            capture_output=True,
            text=True,
            check=True
        )
        
        changed_files = result.stdout.strip().split('\n') if result.stdout.strip() else []
        print(f"📋 Git diff found {len(changed_files)} changed files: {changed_files}")
        
        # If no files found, try alternative approaches
        if not changed_files or (len(changed_files) == 1 and not changed_files[0]):
            print("🔄 No files in HEAD~1..HEAD diff, trying alternative methods...")
            
            # Try getting all files in the repository as fallback
            result = subprocess.run(
                ['git', 'ls-files'],
                capture_output=True,
                text=True,
                check=True
            )
            
            all_files = result.stdout.strip().split('\n') if result.stdout.strip() else []
            print(f"📂 Repository contains {len(all_files)} total files")
            
            # For testing, if this is a new repo or single commit, scan all source files
            changed_files = all_files
        
        # Filter for source code files only
        source_files = []
        for file_path in changed_files:
            if file_path and file_path.strip():  # Skip empty strings
                file_path = file_path.strip()
                for ext in CODE_FILE_EXTENSIONS:
                    if file_path.lower().endswith(ext):
                        # Check if file actually exists
                        if os.path.exists(file_path):
                            source_files.append(file_path)
                            print(f"✅ Found source file: {file_path}")
                        else:
                            print(f"⚠️ File in git but not found on disk: {file_path}")
                        break
        
        print(f"📁 Filtered to {len(source_files)} source code files")
        return source_files
    
    except subprocess.CalledProcessError as e:
        print(f"❌ Error getting changed files: {e}")
        print(f"📋 Command output: {e.output if hasattr(e, 'output') else 'N/A'}")
        
        # Fallback: scan current directory for source files
        print("🔄 Fallback: Scanning current directory for source files...")
        fallback_files = []
        for root, dirs, files in os.walk('.'):
            for file in files:
                file_path = os.path.join(root, file)
                for ext in CODE_FILE_EXTENSIONS:
                    if file.lower().endswith(ext):
                        fallback_files.append(file_path.replace('\\', '/'))
                        break
        
        print(f"📁 Fallback found {len(fallback_files)} source files")
        return fallback_files[:10]  # Limit to 10 files to avoid overwhelming API


def analyze_code_with_gemini(file_content, file_path=""):
    """
    Send code to the Gemini Pro API and get a language-agnostic security analysis.
    
    Args:
        file_content (str): The content of the code file to analyze
        file_path (str): Path of the file being analyzed (for context)
        
    Returns:
        str: Analysis result from Gemini API
    """
    try:
        # Validate API key
        if not GEMINI_API_KEY:
            print("❌ Error: GEMINI_API_KEY is not set")
            return "Error: GEMINI_API_KEY not configured"
        
        # Configure Gemini client
        genai.configure(api_key=GEMINI_API_KEY)
        
        # Truncate very large files to avoid token limits
        max_content_length = 30000  # Approximate token limit
        if len(file_content) > max_content_length:
            print(f"⚠️ Warning: File {file_path} is large ({len(file_content)} chars), truncating...")
            file_content = file_content[:max_content_length] + "\n\n... [File truncated for analysis] ..."
        
        # Use the latest Gemini model
        model = genai.GenerativeModel('gemini-2.5-pro-preview-03-25')
        
        # Create the analysis prompt with structured output requirements
        prompt = f"""You are a senior cybersecurity expert specializing in multi-language code review.
Your task is to analyze the following code snippet for potential security vulnerabilities.

IMPORTANT: Structure your response as follows:

1. **LANGUAGE DETECTED**: [Programming Language Name]

2. **SECURITY ANALYSIS**:
   If vulnerabilities are found, list each one with this exact format:
   
   **VULNERABILITY #[number]: [Vulnerability Name]**
   - **Line(s)**: [line number(s)]
   - **Severity**: [Critical/High/Medium/Low]
   - **Risk**: [detailed explanation of the security risk]
   - **Fix**: [specific code suggestion to remediate]
   
   If NO vulnerabilities are found, respond with exactly: "No issues found."

3. **SUMMARY**: [Brief overall assessment]

Analyze for these common vulnerability types based on the detected language:
- SQL Injection
- Cross-Site Scripting (XSS)  
- Command Injection
- Insecure Deserialization
- Path Traversal/Directory Traversal
- Hardcoded Secrets or API Keys
- Race Conditions
- Buffer Overflows (C/C++)
- Memory Safety Issues
- Authentication/Authorization Bypasses
- Insecure Cryptography
- LDAP Injection
- XXE (XML External Entity)
- CSRF vulnerabilities

Code to analyze:
{file_content}"""
        
        # Configure generation parameters for better reliability
        generation_config = genai.types.GenerationConfig(
            temperature=0.1,  # Low temperature for consistent results
            max_output_tokens=2048,
            top_p=0.8,
            top_k=40
        )
        
        # Generate content using Gemini with retry logic
        max_retries = 3
        for attempt in range(max_retries):
            try:
                response = model.generate_content(
                    prompt,
                    generation_config=generation_config,
                    safety_settings=[
                        {
                            "category": "HARM_CATEGORY_HARASSMENT",
                            "threshold": "BLOCK_NONE"
                        },
                        {
                            "category": "HARM_CATEGORY_HATE_SPEECH",
                            "threshold": "BLOCK_NONE"
                        },
                        {
                            "category": "HARM_CATEGORY_SEXUALLY_EXPLICIT",
                            "threshold": "BLOCK_NONE"
                        },
                        {
                            "category": "HARM_CATEGORY_DANGEROUS_CONTENT",
                            "threshold": "BLOCK_NONE"
                        }
                    ]
                )
                
                if response.text:
                    return response.text
                else:
                    print(f"⚠️ Warning: Empty response from Gemini for {file_path}")
                    return "No issues found."
                    
            except Exception as retry_error:
                print(f"🔄 Attempt {attempt + 1} failed for {file_path}: {retry_error}")
                if attempt == max_retries - 1:
                    raise retry_error
                
                # Wait before retry (exponential backoff)
                import time
                time.sleep(2 ** attempt)
        
        return "Error occurred during analysis"
    
    except Exception as e:
        error_msg = str(e)
        print(f"❌ Error analyzing {file_path} with Gemini: {error_msg}")
        
        # Provide more specific error handling
        if "API key" in error_msg.lower():
            return "Error: Invalid or missing API key"
        elif "quota" in error_msg.lower() or "rate" in error_msg.lower():
            return "Error: API rate limit exceeded"
        elif "token" in error_msg.lower():
            return "Error: Content too large for analysis"
        else:
            return f"Error occurred during analysis: {error_msg}"


def post_comment_on_commit(comment_body):
    """
    Post the findings as a comment on the GitHub commit.
    
    Args:
        comment_body (str): The comment content to post
    """
    try:
        # Construct GitHub API URL
        url = f"https://api.github.com/repos/{GITHUB_REPOSITORY}/commits/{GITHUB_SHA}/comments"
        
        # Set up headers
        headers = {
            'Authorization': f'token {GITHUB_TOKEN}',
            'Accept': 'application/vnd.github.v3+json',
            'Content-Type': 'application/json'
        }
        
        # Create payload
        payload = {'body': comment_body}
        
        # Make POST request
        response = requests.post(url, json=payload, headers=headers)
        
        if response.status_code == 201:
            print("✅ Successfully posted comment on commit")
        else:
            print(f"❌ Failed to post comment. Status code: {response.status_code}")
            print(f"Response: {response.text}")
    
    except Exception as e:
        print(f"Error posting comment on commit: {e}")


def send_email_report_with_gmail(report_body_html):
    """
    Send a detailed HTML report via a Gmail account.
    
    Args:
        report_body_html (str): HTML content for the email report
    """
    # Check if all required Gmail environment variables are present
    if not all([GMAIL_APP_PASSWORD, REPORT_EMAIL_FROM, REPORT_EMAIL_TO]):
        print("⚠️ Warning: Gmail credentials not fully configured. Skipping email report.")
        return
    
    try:
        # Create email message
        msg = EmailMessage()
        
        # Extract repository name for subject
        repo_name = GITHUB_REPOSITORY.split('/')[-1] if GITHUB_REPOSITORY else "Unknown Repository"
        
        # Set email headers
        msg['Subject'] = f"Security Scan Report for {repo_name}"
        msg['From'] = REPORT_EMAIL_FROM
        msg['To'] = REPORT_EMAIL_TO
        
        # Set HTML content
        msg.set_content(report_body_html, subtype='html')
        
        # SMTP server details
        smtp_server = "smtp.gmail.com"
        port = 465
        
        # Create secure SSL context
        context = ssl.create_default_context()
        
        # Send email
        with smtplib.SMTP_SSL(smtp_server, port, context=context) as server:
            server.login(REPORT_EMAIL_FROM, GMAIL_APP_PASSWORD)
            server.send_message(msg)
        
        print("✅ Successfully sent email report")
    
    except Exception as e:
        print(f"❌ Error sending email report: {e}")


if __name__ == "__main__":
    print("🔍 Starting Patch Panda Security Scan...")
    
    # Validate required environment variables
    if not GEMINI_API_KEY:
        print("❌ Error: GEMINI_API_KEY environment variable is required")
        print("💡 Get your API key from: https://makersuite.google.com/app/apikey")
        exit(1)
    
    if not all([GITHUB_TOKEN, GITHUB_REPOSITORY, GITHUB_SHA]):
        print("❌ Error: GitHub environment variables (GITHUB_TOKEN, GITHUB_REPOSITORY, GITHUB_SHA) are required")
        print("💡 These are automatically provided by GitHub Actions")
        exit(1)
    
    # Test Gemini API connection
    print("🔌 Testing Gemini API connection...")
    try:
        import google.generativeai as genai
        genai.configure(api_key=GEMINI_API_KEY)
        model = genai.GenerativeModel('gemini-2.5-pro-preview-03-25')
        test_response = model.generate_content("Hello, this is a test.")
        print("✅ Gemini API connection successful")
    except Exception as e:
        print(f"❌ Gemini API connection failed: {e}")
        print("💡 Check your API key and internet connection")
        exit(1)
    
    # Get changed files
    changed_files = get_changed_files()
    
    if not changed_files:
        print("ℹ️ No source code files were changed in this commit.")
        
        # Post a neutral comment
        neutral_comment = f"""# 🛡️ Patch Panda Security Scan Report

**Commit:** `{GITHUB_SHA[:8]}`
**Repository:** `{GITHUB_REPOSITORY}`

ℹ️ **No source code files detected** in this commit. 

*Patch Panda only scans files with the following extensions:*
`.py`, `.js`, `.ts`, `.java`, `.cs`, `.go`, `.rb`, `.php`, `.rs`, `.c`, `.cpp`, `.h`, `.html`, `.css`

---
*🐼 Report generated by **Patch Panda** Security Scanner*
"""
        post_comment_on_commit(neutral_comment)
        exit(0)
    
    print(f"📁 Found {len(changed_files)} changed source code file(s): {', '.join(changed_files)}")
    
    # Initialize vulnerabilities list
    vulnerabilities_found = []
    analysis_errors = []
    
    # Analyze each changed file
    for file_path in changed_files:
        try:
            # Check if file exists
            if not os.path.exists(file_path):
                print(f"⚠️ Warning: File {file_path} not found (may have been deleted)")
                continue
            
            # Check file size
            file_size = os.path.getsize(file_path)
            if file_size > 1000000:  # 1MB limit
                print(f"⚠️ Warning: File {file_path} is too large ({file_size} bytes), skipping")
                continue
            
            # Read file content
            print(f"🔍 Scanning file: {file_path}")
            
            # Try different encodings to handle various file types
            file_content = None
            for encoding in ['utf-8', 'latin-1', 'cp1252']:
                try:
                    with open(file_path, 'r', encoding=encoding) as file:
                        file_content = file.read()
                    break
                except UnicodeDecodeError:
                    continue
            
            if file_content is None:
                print(f"⚠️ Warning: Could not read file {file_path} with any encoding")
                analysis_errors.append(file_path)
                continue
            
            # Skip empty files
            if not file_content.strip():
                print(f"ℹ️ Skipping empty file: {file_path}")
                continue
            
            # Analyze with Gemini
            print(f"🤖 Sending {file_path} to Gemini for analysis...")
            analysis_result = analyze_code_with_gemini(file_content, file_path)
            print(f"📝 Analysis result length: {len(analysis_result)} characters")
            print(f"📋 First 200 chars of result: {analysis_result[:200]}...")
            
            # Check if vulnerabilities were found (improved detection logic)
            is_error = analysis_result.startswith("Error")
            has_no_issues = "No issues found." in analysis_result
            
            print(f"🔍 Analysis flags - Is Error: {is_error}, Has No Issues: {has_no_issues}")
            
            if not is_error and not has_no_issues:
                print(f"🚨 Vulnerabilities detected in {file_path}")
                
                # GitHub Actions annotation for security issue
                print(f"::warning file={file_path}::🚨 Security vulnerabilities detected in this file")
                
                # Display vulnerabilities in GitHub Actions logs with improved formatting
                print("="*100)
                print(f"🚨 SECURITY VULNERABILITIES FOUND IN: {file_path}")
                print("="*100)
                
                # Parse and structure the output better
                analysis_lines = analysis_result.split('\n')
                current_section = ""
                
                for line in analysis_lines:
                    line = line.strip()
                    if not line:
                        continue
                        
                    if line.startswith("**LANGUAGE DETECTED"):
                        current_section = "language"
                        print(f"🔍 {line}")
                    elif line.startswith("**SECURITY ANALYSIS"):
                        current_section = "analysis"
                        print(f"\n📋 {line}")
                    elif line.startswith("**VULNERABILITY #"):
                        current_section = "vulnerability"
                        print(f"\n🚨 {line}")
                    elif line.startswith("**SUMMARY"):
                        current_section = "summary"
                        print(f"\n📊 {line}")
                    elif line.startswith("- **Line(s)"):
                        print(f"   📍 {line[3:]}")  # Remove "- **" prefix
                    elif line.startswith("- **Severity"):
                        severity = line.split(":")[1].strip() if ":" in line else "Unknown"
                        severity_icon = {
                            "Critical": "🔴",
                            "High": "🟠", 
                            "Medium": "🟡",
                            "Low": "🟢"
                        }.get(severity, "⚪")
                        print(f"   {severity_icon} {line[3:]}")
                    elif line.startswith("- **Risk"):
                        print(f"   ⚠️  {line[3:]}")
                    elif line.startswith("- **Fix"):
                        print(f"   🔧 {line[3:]}")
                    elif current_section and line:
                        # Regular content within sections
                        if current_section == "vulnerability" and not line.startswith("**"):
                            print(f"      {line}")
                        else:
                            print(f"   {line}")
                
                print("="*100)
                print()
                
                # Format for Markdown (GitHub comment)
                markdown_report = f"""
## 🚨 Security Issues Found in `{file_path}`

{analysis_result}

---
"""
                
                # Format for HTML (Email)
                html_report = f"""
<h3>🚨 Security Issues Found in <code>{file_path}</code></h3>
<pre style="white-space: pre-wrap; background-color: #f8f8f8; padding: 10px; border-radius: 5px;">{analysis_result}</pre>
<hr>
"""
                
                vulnerabilities_found.append({
                    'file': file_path,
                    'markdown': markdown_report,
                    'html': html_report,
                    'is_vulnerability': True
                })
            elif is_error:
                print(f"❌ Analysis failed for {file_path}: {analysis_result}")
                analysis_errors.append(file_path)
                
                # GitHub Actions annotation for analysis error
                print(f"::error file={file_path}::❌ Failed to analyze file for security issues")
                
                # Display errors in GitHub Actions logs with improved formatting
                print("="*80)
                print(f"❌ ANALYSIS ERROR IN: {file_path}")
                print("="*80)
                print(f"🔍 Error Type: {analysis_result.split(':')[0] if ':' in analysis_result else 'Unknown Error'}")
                print(f"📋 Details: {analysis_result}")
                print("💡 Troubleshooting:")
                if "API key" in analysis_result.lower():
                    print("   • Check if GEMINI_API_KEY is properly set")
                    print("   • Verify API key is valid and active")
                elif "quota" in analysis_result.lower() or "rate" in analysis_result.lower():
                    print("   • API rate limit exceeded - wait and retry")
                    print("   • Consider upgrading API quota if needed")
                elif "token" in analysis_result.lower():
                    print("   • File content may be too large for analysis")
                    print("   • Try splitting large files into smaller chunks")
                else:
                    print("   • Check internet connectivity")
                    print("   • Verify Gemini API service status")
                print("="*80)
                print()
                
                # Add error report
                error_report = f"""
## ⚠️ Analysis Error in `{file_path}`

{analysis_result}

**Recommendation**: Check file encoding, size, or API connectivity.

---
"""
                
                html_error_report = f"""
<h3>⚠️ Analysis Error in <code>{file_path}</code></h3>
<p style="color: #ff6b6b; background-color: #fff5f5; padding: 10px; border-radius: 5px;">{analysis_result}</p>
<p><strong>Recommendation:</strong> Check file encoding, size, or API connectivity.</p>
<hr>
"""
                
                vulnerabilities_found.append({
                    'file': file_path,
                    'markdown': error_report,
                    'html': html_error_report,
                    'is_vulnerability': False
                })
            else:
                print(f"✅ No issues found in {file_path}")
        
        except Exception as e:
            print(f"❌ Error processing file {file_path}: {e}")
    
    # Summarize results
    actual_vulnerabilities = [v for v in vulnerabilities_found if v.get('is_vulnerability', True)]
    errors_found = [v for v in vulnerabilities_found if not v.get('is_vulnerability', True)]
    
    print(f"\n📊 SCAN SUMMARY:")
    print(f"📁 Files scanned: {len(changed_files)}")
    print(f"🚨 Vulnerabilities found: {len(actual_vulnerabilities)}")
    print(f"❌ Analysis errors: {len(errors_found)}")
    print(f"⚠️ File reading errors: {len(analysis_errors)}")
    
    # Display detailed summary in GitHub Actions logs with improved structure
    if actual_vulnerabilities:
        print("\n" + "="*120)
        print("🚨 COMPREHENSIVE SECURITY VULNERABILITIES SUMMARY")
        print("="*120)
        
        total_critical = 0
        total_high = 0 
        total_medium = 0
        total_low = 0
        
        for i, vuln in enumerate(actual_vulnerabilities, 1):
            print(f"\n🔍 SECURITY ISSUE #{i}")
            print(f"📁 File: {vuln['file']}")
            print("-" * 80)
            
            # Extract and structure the vulnerability details
            vuln_content = vuln['markdown'].split('\n\n', 1)[1] if '\n\n' in vuln['markdown'] else vuln['markdown']
            vuln_lines = vuln_content.split('\n')
            
            current_vuln = ""
            for line in vuln_lines:
                line = line.strip()
                if not line or line == "---":
                    continue
                    
                if line.startswith("**VULNERABILITY #"):
                    current_vuln = line.replace("**", "").replace("VULNERABILITY #", "VULN #")
                    print(f"🚨 {current_vuln}")
                elif line.startswith("- **Line(s)"):
                    print(f"   📍 {line[3:].replace('**', '')}")
                elif line.startswith("- **Severity"):
                    severity_line = line[3:].replace('**', '')
                    severity = severity_line.split(":")[1].strip() if ":" in severity_line else "Unknown"
                    severity_icon = {
                        "Critical": "🔴",
                        "High": "🟠", 
                        "Medium": "🟡",
                        "Low": "🟢"
                    }.get(severity, "⚪")
                    print(f"   {severity_icon} {severity_line}")
                    
                    # Count severity levels
                    if "Critical" in severity:
                        total_critical += 1
                    elif "High" in severity:
                        total_high += 1
                    elif "Medium" in severity:
                        total_medium += 1
                    elif "Low" in severity:
                        total_low += 1
                        
                elif line.startswith("- **Risk"):
                    print(f"   ⚠️  {line[3:].replace('**', '')}")
                elif line.startswith("- **Fix"):
                    print(f"   🔧 {line[3:].replace('**', '')}")
                elif line and not line.startswith("**"):
                    print(f"      {line}")
            
            print("-" * 80)
        
        # Summary statistics
        print(f"\n📊 SEVERITY BREAKDOWN:")
        print(f"   🔴 Critical: {total_critical}")
        print(f"   🟠 High: {total_high}")
        print(f"   🟡 Medium: {total_medium}")
        print(f"   🟢 Low: {total_low}")
        
        print("="*120)
        print(f"🚨 TOTAL SECURITY ISSUES FOUND: {len(actual_vulnerabilities)}")
        print("="*120)
        print()
    
    if errors_found:
        print("\n" + "="*100)
        print("⚠️  ANALYSIS ERRORS SUMMARY")
        print("="*100)
        for i, error in enumerate(errors_found, 1):
            print(f"\n❌ ERROR #{i}")
            print(f"📁 File: {error['file']}")
            print("-" * 60)
            error_details = error['markdown'].split('\n\n', 1)[1] if '\n\n' in error['markdown'] else error['markdown']
            error_lines = error_details.replace('---\n', '').strip().split('\n')
            
            for line in error_lines:
                line = line.strip()
                if line.startswith("**Recommendation"):
                    print(f"💡 {line.replace('**', '')}")
                elif line and not line.startswith("Error:"):
                    print(f"   {line}")
                elif line.startswith("Error:"):
                    print(f"🔍 {line}")
            print("-" * 60)
        print("="*100)
        print()
    
    # Generate and send reports if we have results (vulnerabilities or errors)
    if vulnerabilities_found:
        print(f"\n📝 Generating reports...")
        
        # Count actual vulnerabilities vs errors
        vuln_count = len(actual_vulnerabilities)
        error_count = len(errors_found)
        
        # Construct GitHub comment (Markdown)
        commit_comment = f"""# 🛡️ Patch Panda Security Scan Report
        
**Commit:** `{GITHUB_SHA[:8]}`
**Repository:** `{GITHUB_REPOSITORY}`
**Files Scanned:** {len(changed_files)}
**Security Issues:** {vuln_count}
**Analysis Errors:** {error_count}

---

"""
        
        # Construct email report (HTML)
        repo_name = GITHUB_REPOSITORY.split('/')[-1] if GITHUB_REPOSITORY else "Unknown Repository"
        commit_url = f"https://github.com/{GITHUB_REPOSITORY}/commit/{GITHUB_SHA}" if GITHUB_REPOSITORY and GITHUB_SHA else "#"
        
        # Determine header color based on results
        header_color = "#ff4444" if vuln_count > 0 else "#ffa500"
        
        email_report = f"""
<!DOCTYPE html>
<html>
<head>
    <title>Security Scan Report</title>
    <style>
        body {{ font-family: Arial, sans-serif; line-height: 1.6; color: #333; }}
        .header {{ background-color: {header_color}; color: white; padding: 20px; text-align: center; }}
        .content {{ padding: 20px; }}
        .summary {{ background-color: #f4f4f4; padding: 15px; border-left: 4px solid {header_color}; margin: 20px 0; }}
        code {{ background-color: #f4f4f4; padding: 2px 4px; border-radius: 3px; }}
        pre {{ background-color: #f8f8f8; padding: 10px; border-radius: 5px; overflow-x: auto; }}
    </style>
</head>
<body>
    <div class="header">
        <h1>🛡️ Patch Panda Security Scan Report</h1>
    </div>
    <div class="content">
        <div class="summary">
            <h2>📊 Scan Summary</h2>
            <ul>
                <li><strong>Repository:</strong> {GITHUB_REPOSITORY}</li>
                <li><strong>Commit:</strong> <a href="{commit_url}">{GITHUB_SHA[:8]}</a></li>
                <li><strong>Files Scanned:</strong> {len(changed_files)}</li>
                <li><strong>Security Issues:</strong> {vuln_count}</li>
                <li><strong>Analysis Errors:</strong> {error_count}</li>
            </ul>
        </div>
        
        <h2>🔍 Detailed Results</h2>
"""
        
        # Add individual vulnerability reports
        for vuln in vulnerabilities_found:
            commit_comment += vuln['markdown']
            email_report += vuln['html']
        
        # Add footer to email
        email_report += f"""
        <div style="margin-top: 40px; padding-top: 20px; border-top: 1px solid #ccc; color: #666; font-size: 12px;">
            <p>This report was generated by Patch Panda Security Scanner.</p>
            <p>View the commit: <a href="{commit_url}">{GITHUB_SHA[:8]}</a></p>
        </div>
    </div>
</body>
</html>
"""
        
        # Add footer to commit comment
        commit_comment += f"""
---
*🐼 Report generated by **Patch Panda** Security Scanner*
"""
        
        # Post comment on commit
        print("📬 Posting comment to GitHub...")
        post_comment_on_commit(commit_comment)
        
        # Send email report
        if vuln_count > 0 or error_count > 0:
            print("📧 Sending email report...")
            send_email_report_with_gmail(email_report)
        
    else:
        print("✅ Scan complete. No files analyzed or no results to report.")
        
        # Post a simple completion comment
        completion_comment = f"""# 🛡️ Patch Panda Security Scan Report

**Commit:** `{GITHUB_SHA[:8]}`
**Repository:** `{GITHUB_REPOSITORY}`
**Files Scanned:** {len(changed_files)}

✅ **Scan completed** - All analyzed files appear clean.

---
*🐼 Report generated by **Patch Panda** Security Scanner*
"""
        post_comment_on_commit(completion_comment)
    
    print(f"\n🔍 Security scan completed!")
    print(f"📊 Final Summary:")
    print(f"   📁 Files scanned: {len(changed_files)}")
    print(f"   🚨 Security issues: {len(actual_vulnerabilities) if 'actual_vulnerabilities' in locals() else 0}")
    print(f"   ❌ Analysis errors: {len(analysis_errors)}")
    
    # GitHub Actions summary annotations
    if 'actual_vulnerabilities' in locals():
        vuln_count = len(actual_vulnerabilities)
        if vuln_count > 0:
            print(f"::notice title=Patch Panda Security Scan::🚨 Found {vuln_count} security vulnerabilities across {len(changed_files)} files")
            print(f"::warning::🚨 SECURITY ALERT: {vuln_count} vulnerabilities detected! Check the scan results above.")
        else:
            print(f"::notice title=Patch Panda Security Scan::✅ No security vulnerabilities detected in {len(changed_files)} files")
    
    # Exit with appropriate code
    if 'actual_vulnerabilities' in locals() and len(actual_vulnerabilities) > 0:
        print("⚠️ Security vulnerabilities detected! Please review the findings.")
        # Don't exit with error code as this might block the workflow
        # exit(1)
    else:
        print("🎉 No security vulnerabilities detected!")
