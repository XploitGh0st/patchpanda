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
        # Run git command to get changed files
        result = subprocess.run(
            ['git', 'diff', '--name-only', 'HEAD~1', 'HEAD'],
            capture_output=True,
            text=True,
            check=True
        )
        
        # Get list of all changed files
        changed_files = result.stdout.strip().split('\n')
        
        # Filter for source code files only
        source_files = []
        for file_path in changed_files:
            if file_path:  # Skip empty strings
                for ext in CODE_FILE_EXTENSIONS:
                    if file_path.lower().endswith(ext):
                        source_files.append(file_path)
                        break
        
        return source_files
    
    except subprocess.CalledProcessError as e:
        print(f"Error getting changed files: {e}")
        return []


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
        
        # Use the newer model name
        model = genai.GenerativeModel('gemini-1.5-flash')
        
        # Create the analysis prompt
        prompt = f"""You are a senior cybersecurity expert specializing in multi-language code review.
Your task is to analyze the following code snippet for potential security vulnerabilities.

First, identify the programming language of the code.
Then, based on the identified language, analyze the code for common security vulnerabilities relevant to that language. Examples include, but are not limited to:
- SQL Injection
- Cross-Site Scripting (XSS)
- Command Injection
- Insecure Deserialization
- Insecure File Handling (e.g., Path Traversal)
- Hardcoded Secrets or API Keys
- Race Conditions or Memory Safety Issues (for languages like C++, Rust, Go)

For each vulnerability you find, provide:
1. A clear title for the vulnerability.
2. The line number where the issue occurs.
3. A detailed explanation of the risk.
4. A secure code snippet suggesting how to fix it.

If the code appears to be secure and you find no vulnerabilities, you MUST respond with the exact phrase: 'No issues found.'.

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
        model = genai.GenerativeModel('gemini-1.5-flash')
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
            analysis_result = analyze_code_with_gemini(file_content, file_path)
            
            # Check if vulnerabilities were found (improved error detection)
            if ("No issues found." not in analysis_result and 
                not analysis_result.startswith("Error")):
                print(f"🚨 Vulnerabilities detected in {file_path}")
                
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
                    'html': html_report
                })
            elif analysis_result.startswith("Error"):
                print(f"❌ Analysis failed for {file_path}: {analysis_result}")
                
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
                    'html': html_error_report
                })
            else:
                print(f"✅ No issues found in {file_path}")
        
        except Exception as e:
            print(f"❌ Error processing file {file_path}: {e}")
    
    # Generate and send reports if vulnerabilities were found
    if vulnerabilities_found:
        print(f"\n🚨 SECURITY ALERT: Found vulnerabilities in {len(vulnerabilities_found)} file(s)")
        
        # Construct GitHub comment (Markdown)
        commit_comment = f"""# 🛡️ Patch Panda Security Scan Report
        
**Commit:** `{GITHUB_SHA[:8]}`
**Repository:** `{GITHUB_REPOSITORY}`
**Files Scanned:** {len(changed_files)}
**Vulnerabilities Found:** {len(vulnerabilities_found)}

---

"""
        
        # Construct email report (HTML)
        repo_name = GITHUB_REPOSITORY.split('/')[-1] if GITHUB_REPOSITORY else "Unknown Repository"
        commit_url = f"https://github.com/{GITHUB_REPOSITORY}/commit/{GITHUB_SHA}" if GITHUB_REPOSITORY and GITHUB_SHA else "#"
        
        email_report = f"""
<!DOCTYPE html>
<html>
<head>
    <title>Security Scan Report</title>
    <style>
        body {{ font-family: Arial, sans-serif; line-height: 1.6; color: #333; }}
        .header {{ background-color: #ff4444; color: white; padding: 20px; text-align: center; }}
        .content {{ padding: 20px; }}
        .summary {{ background-color: #f4f4f4; padding: 15px; border-left: 4px solid #ff4444; margin: 20px 0; }}
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
                <li><strong>Vulnerabilities Found:</strong> {len(vulnerabilities_found)}</li>
            </ul>
        </div>
        
        <h2>🚨 Detailed Findings</h2>
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
        post_comment_on_commit(commit_comment)
        
        # Send email report
        send_email_report_with_gmail(email_report)
        
    else:
        print("✅ Scan complete. No vulnerabilities found in the changed files.")
        
        # Post a positive comment on commit
        positive_comment = f"""# 🛡️ Patch Panda Security Scan Report

**Commit:** `{GITHUB_SHA[:8]}`
**Repository:** `{GITHUB_REPOSITORY}`
**Files Scanned:** {len(changed_files)}

✅ **All clear!** No security vulnerabilities detected in the changed files.

---
*🐼 Report generated by **Patch Panda** Security Scanner*
"""
        post_comment_on_commit(positive_comment)
    
    print("🔍 Security scan completed!")

#hello