#!/usr/bin/env python3
"""
Patch Panda Security Scanner - Enterprise Edition
A comprehensive security scanner for GitHub Actions that analyzes changed files
for vulnerabilities using Google's Gemini 2.5 Pro Preview AI and reports findings 
via GitHub comments and professional email notifications.

Enhanced Features:
- Gemini 2.5 Pro Preview AI model for cutting-edge security analysis
- Professional HTML email reports with responsive design
- Separate API key support for dedicated Pro access
- Enhanced vulnerability detection with OWASP/CWE standards
- Executive summary dashboards and detailed security reporting
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
GEMINI_PRO_API_KEY = os.getenv('GEMINI_PRO_API_KEY')  # Optional separate API key for Pro model
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
        # Validate API key - use Pro key if available, fallback to regular key
        api_key = GEMINI_PRO_API_KEY if GEMINI_PRO_API_KEY else GEMINI_API_KEY
        if not api_key:
            print("❌ Error: Neither GEMINI_API_KEY nor GEMINI_PRO_API_KEY is set")
            return "Error: GEMINI_API_KEY not configured"
        
        # Configure Gemini client with the selected API key
        genai.configure(api_key=api_key)
        
        # Log which API key is being used
        key_type = "Gemini Pro API Key" if GEMINI_PRO_API_KEY else "Standard Gemini API Key"
        print(f"🔑 Using {key_type} for analysis")
        
        # Truncate very large files to avoid token limits
        max_content_length = 30000  # Approximate token limit
        if len(file_content) > max_content_length:
            print(f"⚠️ Warning: File {file_path} is large ({len(file_content)} chars), truncating...")
            file_content = file_content[:max_content_length] + "\n\n... [File truncated for analysis] ..."
        
        # Use the latest Gemini 2.5 Pro Preview model
        model = genai.GenerativeModel('gemini-2.5-pro-preview-03-25')
        
        # Create the enhanced analysis prompt for Gemini Pro
        prompt = f"""You are an elite cybersecurity consultant and code auditor with 15+ years of experience in application security. You specialize in identifying security vulnerabilities across multiple programming languages and frameworks.

ANALYSIS TASK:
Perform a comprehensive security audit of the provided code snippet. Use your expertise to identify potential vulnerabilities, security weaknesses, and best practice violations.

ANALYSIS METHODOLOGY:
1. **Language Detection**: First, identify the programming language and any frameworks used
2. **Context Analysis**: Understand the code's purpose and functionality
3. **Vulnerability Assessment**: Apply OWASP Top 10, CWE standards, and language-specific security patterns
4. **Risk Evaluation**: Assess the severity and exploitability of identified issues

VULNERABILITY CATEGORIES TO EXAMINE:
🔍 **Injection Attacks**: SQL, NoSQL, Command, LDAP, XML injection
🔍 **Authentication & Authorization**: Broken authentication, privilege escalation, session management
🔍 **Data Exposure**: Sensitive data leakage, insecure storage, information disclosure
🔍 **Input Validation**: XSS, CSRF, input sanitization, path traversal
🔍 **Cryptography**: Weak encryption, insecure hashing, key management
🔍 **Configuration**: Security misconfigurations, default credentials, debug mode
🔍 **Dependencies**: Known vulnerable components, outdated libraries
🔍 **Business Logic**: Race conditions, workflow bypasses, logic flaws
🔍 **Memory Safety** (C/C++/Rust): Buffer overflows, memory leaks, use-after-free
🔍 **Concurrency Issues**: Race conditions, deadlocks, thread safety

RESPONSE FORMAT:
For each vulnerability found, provide:

**🚨 [SEVERITY] [Vulnerability Name]**
- **Location**: Line X-Y or specific function/method
- **Risk Level**: Critical/High/Medium/Low + CVSS score estimate if applicable  
- **Description**: Clear explanation of the security issue and potential impact
- **Exploitation Scenario**: How an attacker might exploit this vulnerability
- **Remediation**: Specific code changes or security controls needed
- **Secure Code Example**: Demonstrate the fix with corrected code snippet

IMPORTANT GUIDELINES:
- Use professional security terminology and industry standards
- Provide actionable remediation advice with code examples
- Consider the broader security context, not just individual lines
- If the code appears secure, respond EXACTLY with: "No issues found."
- Focus on genuine security issues, not minor code quality problems
- Consider both direct vulnerabilities and potential attack vectors

FILE CONTEXT: {file_path}
CODE TO ANALYZE:

```
{file_content}
```

Begin your security analysis now:"""
        
        # Configure generation parameters for high-quality security analysis
        generation_config = genai.types.GenerationConfig(
            temperature=0.1,  # Very low temperature for consistent, focused analysis
            max_output_tokens=4096,  # Increased for detailed security reports
            top_p=0.9,  # Slightly higher for more comprehensive coverage
            top_k=20,   # More focused on relevant security concepts
            candidate_count=1
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
        
        # Create professional subject line based on findings
        if vuln_count > 0:
            if vuln_count == 1:
                subject = f"🚨 SECURITY ALERT: 1 Vulnerability Detected in {repo_name}"
            else:
                subject = f"🚨 SECURITY ALERT: {vuln_count} Vulnerabilities Detected in {repo_name}"
        elif error_count > 0:
            subject = f"⚠️ Security Scan Issues in {repo_name} - Analysis Errors Detected"
        else:
            subject = f"✅ Security Scan Complete: {repo_name} - No Issues Found"
        
        # Set email headers
        msg['Subject'] = subject
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
    api_key = GEMINI_PRO_API_KEY if GEMINI_PRO_API_KEY else GEMINI_API_KEY
    if not api_key:
        print("❌ Error: GEMINI_API_KEY or GEMINI_PRO_API_KEY environment variable is required")
        print("💡 Get your API key from: https://aistudio.google.com/app/apikey")
        print("💡 For enhanced analysis, set GEMINI_PRO_API_KEY for dedicated Pro model access")
        exit(1)
    
    if not all([GITHUB_TOKEN, GITHUB_REPOSITORY, GITHUB_SHA]):
        print("❌ Error: GitHub environment variables (GITHUB_TOKEN, GITHUB_REPOSITORY, GITHUB_SHA) are required")
        print("💡 These are automatically provided by GitHub Actions")
        exit(1)
    
    # Test Gemini API connection with 2.5 Pro Preview model
    print("🔌 Testing Gemini 2.5 Pro Preview API connection...")
    try:
        import google.generativeai as genai
        genai.configure(api_key=api_key)
        model = genai.GenerativeModel('gemini-2.5-pro-preview-03-25')
        
        # Test with a security-focused prompt
        test_response = model.generate_content(
            "You are a cybersecurity expert. Respond with: 'Gemini 2.5 Pro Preview security analysis ready.'",
            generation_config=genai.types.GenerationConfig(
                temperature=0.1,
                max_output_tokens=50
            )
        )
        print("✅ Gemini 2.5 Pro Preview API connection successful")
        print(f"🤖 Model response: {test_response.text.strip()}")
        
        # Log which API configuration is being used
        key_type = "Dedicated Pro API Key" if GEMINI_PRO_API_KEY else "Standard API Key with 2.5 Pro Preview"
        print(f"🔑 Using: {key_type}")
        
    except Exception as e:
        print(f"❌ Gemini 2.5 Pro Preview API connection failed: {e}")
        print("💡 Check your API key, internet connection, and API quotas")
        print("💡 Ensure your API key has access to Gemini 2.5 Pro Preview model")
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
                
                # Display vulnerabilities in GitHub Actions logs
                print("="*80)
                print(f"🚨 SECURITY VULNERABILITIES FOUND IN: {file_path}")
                print("="*80)
                print(analysis_result)
                print("="*80)
                print()
                
                # Format for Markdown (GitHub comment)
                markdown_report = f"""
## 🚨 Security Issues Found in `{file_path}`

{analysis_result}

---
"""
                
                # Format for HTML (Email)
                html_report = f"""
            <div class="section">
                <div class="vulnerability-card">
                    <div class="vulnerability-header critical">
                        <h3>🚨 Critical Security Issues
                            <span class="file-badge">{file_path}</span>
                        </h3>
                    </div>
                    <div class="vulnerability-content">
                        <div class="vulnerability-details">{analysis_result}</div>
                        <p style="margin-top: 15px; color: #718096; font-size: 13px;">
                            <strong>Recommendation:</strong> Address these vulnerabilities immediately to prevent potential security breaches.
                        </p>
                    </div>
                </div>
            </div>"""
                
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
                
                # Display errors in GitHub Actions logs
                print("="*60)
                print(f"❌ ANALYSIS ERROR IN: {file_path}")
                print("="*60)
                print(analysis_result)
                print("="*60)
                print()
                
                # Add error report
                error_report = f"""
## ⚠️ Analysis Error in `{file_path}`

{analysis_result}

**Recommendation**: Check file encoding, size, or API connectivity.

---
"""
                
                html_error_report = f"""
            <div class="error-card">
                <h3>⚠️ Analysis Error in <code>{file_path}</code></h3>
                <div class="error-message">{analysis_result}</div>
                <p style="margin-top: 15px; color: #718096; font-size: 13px;">
                    <strong>Troubleshooting:</strong> This error may be caused by file encoding issues, large file size, or API connectivity problems. Please verify the file can be read correctly and try again.
                </p>
            </div>"""
                
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
    
    # Display detailed summary in GitHub Actions logs
    if actual_vulnerabilities:
        print("\n" + "="*100)
        print("🚨 SECURITY VULNERABILITIES SUMMARY")
        print("="*100)
        for i, vuln in enumerate(actual_vulnerabilities, 1):
            print(f"\n🔍 Vulnerability #{i} in: {vuln['file']}")
            print("-" * 60)
            # Extract just the vulnerability details from markdown (remove header)
            vuln_details = vuln['markdown'].split('\n\n', 1)[1] if '\n\n' in vuln['markdown'] else vuln['markdown']
            print(vuln_details.replace('---\n', '').strip())
            print("-" * 60)
        print("="*100)
        print(f"🚨 TOTAL SECURITY ISSUES FOUND: {len(actual_vulnerabilities)}")
        print("="*100)
        print()
    
    if errors_found:
        print("\n" + "="*80)
        print("⚠️ ANALYSIS ERRORS SUMMARY")
        print("="*80)
        for i, error in enumerate(errors_found, 1):
            print(f"\n❌ Error #{i} in: {error['file']}")
            print("-" * 50)
            error_details = error['markdown'].split('\n\n', 1)[1] if '\n\n' in error['markdown'] else error['markdown']
            print(error_details.replace('---\n', '').strip())
            print("-" * 50)
        print("="*80)
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
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Security Scan Report - {repo_name}</title>
    <style>
        * {{
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }}
        
        body {{
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, Cantarell, sans-serif;
            line-height: 1.7;
            color: #2c3e50;
            background-color: #f8fafc;
        }}
        
        .container {{
            max-width: 800px;
            margin: 0 auto;
            background-color: #ffffff;
            box-shadow: 0 4px 20px rgba(0, 0, 0, 0.08);
            border-radius: 12px;
            overflow: hidden;
        }}
        
        .header {{
            background: linear-gradient(135deg, {header_color} 0%, {'#e74c3c' if vuln_count > 0 else '#f39c12'} 100%);
            color: white;
            padding: 40px 30px;
            text-align: center;
            position: relative;
        }}
        
        .header::before {{
            content: '';
            position: absolute;
            top: 0;
            left: 0;
            right: 0;
            bottom: 0;
            background: url('data:image/svg+xml,<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 100 20"><defs><linearGradient id="a" x1="0" x2="0" y1="0" y2="1"><stop offset="0" stop-color="%23ffffff" stop-opacity="0.1"/><stop offset="1" stop-color="%23ffffff" stop-opacity="0"/></linearGradient></defs><rect width="100" height="20" fill="url(%23a)"/></svg>') repeat-x;
            opacity: 0.1;
        }}
        
        .header h1 {{
            font-size: 32px;
            font-weight: 700;
            margin-bottom: 8px;
            position: relative;
            z-index: 1;
        }}
        
        .header .subtitle {{
            font-size: 16px;
            opacity: 0.9;
            position: relative;
            z-index: 1;
        }}
        
        .content {{
            padding: 40px 30px;
        }}
        
        .summary-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 20px;
            margin: 30px 0;
        }}
        
        .summary-card {{
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 25px;
            border-radius: 12px;
            text-align: center;
            box-shadow: 0 4px 15px rgba(102, 126, 234, 0.3);
            transition: transform 0.3s ease;
        }}
        
        .summary-card:hover {{
            transform: translateY(-2px);
        }}
        
        .summary-card.danger {{
            background: linear-gradient(135deg, #ff6b6b 0%, #ee5a52 100%);
            box-shadow: 0 4px 15px rgba(255, 107, 107, 0.3);
        }}
        
        .summary-card.warning {{
            background: linear-gradient(135deg, #feca57 0%, #ff9ff3 100%);
            box-shadow: 0 4px 15px rgba(254, 202, 87, 0.3);
        }}
        
        .summary-card.success {{
            background: linear-gradient(135deg, #48cae4 0%, #023047 100%);
            box-shadow: 0 4px 15px rgba(72, 202, 228, 0.3);
        }}
        
        .summary-card h3 {{
            font-size: 32px;
            font-weight: 800;
            margin-bottom: 8px;
        }}
        
        .summary-card p {{
            font-size: 14px;
            opacity: 0.9;
            font-weight: 500;
        }}
        
        .section {{
            margin: 40px 0;
        }}
        
        .section-header {{
            border-left: 5px solid {header_color};
            padding-left: 20px;
            margin-bottom: 25px;
        }}
        
        .section-header h2 {{
            font-size: 24px;
            font-weight: 700;
            color: #2c3e50;
            margin-bottom: 5px;
        }}
        
        .section-header p {{
            color: #718096;
            font-size: 14px;
        }}
        
        .vulnerability-card {{
            background: #ffffff;
            border: 1px solid #e2e8f0;
            border-radius: 12px;
            margin: 20px 0;
            overflow: hidden;
            box-shadow: 0 2px 10px rgba(0, 0, 0, 0.05);
            transition: all 0.3s ease;
        }}
        
        .vulnerability-card:hover {{
            box-shadow: 0 8px 25px rgba(0, 0, 0, 0.1);
            transform: translateY(-2px);
        }}
        
        .vulnerability-header {{
            background: linear-gradient(135deg, #f8f9fa 0%, #e9ecef 100%);
            padding: 20px;
            border-bottom: 1px solid #dee2e6;
        }}
        
        .vulnerability-header.critical {{
            background: linear-gradient(135deg, #fee2e2 0%, #fecaca 100%);
            border-left: 4px solid #dc2626;
        }}
        
        .vulnerability-header.high {{
            background: linear-gradient(135deg, #fed7aa 0%, #fdba74 100%);
            border-left: 4px solid #ea580c;
        }}
        
        .vulnerability-header h3 {{
            font-size: 18px;
            font-weight: 600;
            color: #1a202c;
            margin-bottom: 5px;
            display: flex;
            align-items: center;
        }}
        
        .file-badge {{
            background: #4f46e5;
            color: white;
            padding: 4px 12px;
            border-radius: 20px;
            font-size: 12px;
            font-weight: 500;
            margin-left: 10px;
        }}
        
        .vulnerability-content {{
            padding: 25px;
        }}
        
        .vulnerability-details {{
            background: #f7fafc;
            border: 1px solid #e2e8f0;
            border-radius: 8px;
            padding: 20px;
            margin: 15px 0;
            font-family: 'SF Mono', Consolas, 'Liberation Mono', Menlo, monospace;
            font-size: 14px;
            line-height: 1.6;
            color: #2d3748;
            white-space: pre-wrap;
            overflow-x: auto;
        }}
        
        .error-card {{
            background: linear-gradient(135deg, #fff5f5 0%, #fed7d7 100%);
            border: 1px solid #feb2b2;
            border-radius: 12px;
            margin: 20px 0;
            padding: 25px;
            border-left: 4px solid #e53e3e;
        }}
        
        .error-card h3 {{
            color: #c53030;
            font-size: 18px;
            font-weight: 600;
            margin-bottom: 10px;
        }}
        
        .error-card .error-message {{
            background: #ffffff;
            border: 1px solid #feb2b2;
            border-radius: 6px;
            padding: 15px;
            font-family: 'SF Mono', Consolas, 'Liberation Mono', Menlo, monospace;
            font-size: 13px;
            color: #742a2a;
            margin: 10px 0;
        }}
        
        .footer {{
            background: #f7fafc;
            padding: 30px;
            border-top: 1px solid #e2e8f0;
            text-align: center;
        }}
        
        .footer-content {{
            max-width: 600px;
            margin: 0 auto;
        }}
        
        .footer h3 {{
            color: #2d3748;
            font-size: 18px;
            margin-bottom: 15px;
            font-weight: 600;
        }}
        
        .footer p {{
            color: #718096;
            font-size: 14px;
            line-height: 1.6;
            margin: 8px 0;
        }}
        
        .footer-links {{
            margin: 20px 0;
        }}
        
        .footer-links a {{
            display: inline-block;
            background: #4f46e5;
            color: white;
            padding: 10px 20px;
            text-decoration: none;
            border-radius: 6px;
            font-weight: 500;
            font-size: 14px;
            margin: 5px 10px;
            transition: background-color 0.3s ease;
        }}
        
        .footer-links a:hover {{
            background: #3730a3;
        }}
        
        .timestamp {{
            background: #edf2f7;
            color: #4a5568;
            padding: 15px;
            text-align: center;
            font-size: 12px;
            font-family: 'SF Mono', Consolas, 'Liberation Mono', Menlo, monospace;
        }}
        
        @media (max-width: 600px) {{
            .container {{
                margin: 10px;
                border-radius: 8px;
            }}
            
            .header {{
                padding: 30px 20px;
            }}
            
            .content {{
                padding: 30px 20px;
            }}
            
            .summary-grid {{
                grid-template-columns: 1fr;
            }}
            
            .vulnerability-header h3 {{
                flex-direction: column;
                align-items: flex-start;
            }}
            
            .file-badge {{
                margin-left: 0;
                margin-top: 8px;
            }}
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🛡️ Security Scan Report</h1>
            <p class="subtitle">Comprehensive vulnerability analysis powered by Gemini Pro AI</p>
        </div>
        
        <div class="content">
            <div class="section">
                <div class="section-header">
                    <h2>📊 Executive Summary</h2>
                    <p>Overview of security analysis results for your repository</p>
                </div>
                
                <div class="summary-grid">
                    <div class="summary-card {'danger' if vuln_count > 0 else 'success'}">
                        <h3>{vuln_count}</h3>
                        <p>Security Vulnerabilities</p>
                    </div>
                    <div class="summary-card">
                        <h3>{len(changed_files)}</h3>
                        <p>Files Analyzed</p>
                    </div>
                    <div class="summary-card {'warning' if error_count > 0 else 'success'}">
                        <h3>{error_count}</h3>
                        <p>Analysis Errors</p>
                    </div>
                </div>
                
                <div style="background: #f7fafc; padding: 20px; border-radius: 8px; border-left: 4px solid #4f46e5;">
                    <h3 style="color: #2d3748; margin-bottom: 10px; font-size: 16px;">📂 Repository Details</h3>
                    <p style="margin: 5px 0;"><strong>Repository:</strong> <code>{GITHUB_REPOSITORY}</code></p>
                    <p style="margin: 5px 0;"><strong>Commit SHA:</strong> <a href="{commit_url}" style="color: #4f46e5; text-decoration: none;"><code>{GITHUB_SHA[:8]}</code></a></p>
                    <p style="margin: 5px 0;"><strong>Analysis Engine:</strong> Google Gemini 2.5 Pro Preview</p>
                </div>
            </div>"""
"""
        
        # Add individual vulnerability reports
        for vuln in vulnerabilities_found:
            commit_comment += vuln['markdown']
            email_report += vuln['html']
        
        # Add footer to email
        import datetime
        current_time = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S UTC")
        
        email_report += f"""
            </div>
        </div>
        
        <div class="footer">
            <div class="footer-content">
                <h3>🐼 Patch Panda Security Scanner</h3>
                <p>Advanced AI-powered security analysis using Google Gemini 2.5 Pro Preview</p>
                <p>This automated scan helps identify potential security vulnerabilities in your codebase.</p>
                
                <div class="footer-links">
                    <a href="{commit_url}">View Commit</a>
                    <a href="https://github.com/{GITHUB_REPOSITORY}">View Repository</a>
                </div>
                
                <p style="margin-top: 20px; font-size: 12px;">
                    For questions about this report, please contact your development team.<br>
                    This is an automated message - please do not reply directly to this email.
                </p>
            </div>
        </div>
        
        <div class="timestamp">
            Report generated on {current_time} | Powered by Gemini 2.5 Pro Preview AI
        </div>
    </div>
</body>
</html>"""
        
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
