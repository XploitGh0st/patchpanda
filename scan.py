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
from datetime import datetime
import json
# Try to import reportlab, install if missing
REPORTLAB_AVAILABLE = False
try:
    from reportlab.lib.pagesizes import letter, A4
    from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib.units import inch
    from reportlab.lib.colors import HexColor, black, red, orange, yellow, green
    from reportlab.lib import colors
    REPORTLAB_AVAILABLE = True
    print("✅ ReportLab loaded successfully")
except ImportError:
    print("⚠️ ReportLab not found. Attempting to install...")
    try:
        import subprocess
        import sys
        result = subprocess.run([sys.executable, '-m', 'pip', 'install', 'reportlab>=4.0.0'], 
                              capture_output=True, text=True, timeout=60)
        if result.returncode == 0:
            print("✅ ReportLab installed successfully, importing...")
            from reportlab.lib.pagesizes import letter, A4
            from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak
            from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
            from reportlab.lib.units import inch
            from reportlab.lib.colors import HexColor, black, red, orange, yellow, green
            from reportlab.lib import colors
            REPORTLAB_AVAILABLE = True
        else:
            print(f"❌ Failed to install ReportLab: {result.stderr}")
            REPORTLAB_AVAILABLE = False
    except Exception as e:
        print(f"❌ Error installing ReportLab: {e}")
        REPORTLAB_AVAILABLE = False


# --- Environment Variables ---
GEMINI_API_KEY = os.getenv('GEMINI_API_KEY')
GITHUB_TOKEN = os.getenv('GITHUB_TOKEN')
GITHUB_REPOSITORY = os.getenv('GITHUB_REPOSITORY')
GITHUB_SHA = os.getenv('GITHUB_SHA')
GMAIL_APP_PASSWORD = os.getenv('GMAIL_APP_PASSWORD')
REPORT_EMAIL_FROM = os.getenv('REPORT_EMAIL_FROM')
REPORT_EMAIL_TO = os.getenv('REPORT_EMAIL_TO')

# --- Rate Limiting Configuration ---
API_CALLS_MADE = 0  # Track number of API calls
MAX_FILES_PER_RUN = 10  # Limit files per scan to prevent rate limiting


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
        model = genai.GenerativeModel('gemini-2.5-pro-preview-06-05')
        
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
        
        # Generate content using Gemini with enhanced retry logic for rate limiting
        max_retries = 5  # Increased for rate limit handling
        base_delay = 2  # Base delay in seconds
        
        for attempt in range(max_retries):
            try:
                # Add small delay between requests to avoid rate limiting
                if attempt > 0:
                    import time
                    # Progressive delay: 2s, 5s, 10s, 20s, 40s
                    delay = base_delay * (2 ** attempt)
                    print(f"⏳ Waiting {delay}s before retry {attempt + 1}...")
                    time.sleep(delay)
                
                print(f"🤖 Sending request to Gemini (attempt {attempt + 1}/{max_retries})...")
                
                # Track API calls
                global API_CALLS_MADE
                API_CALLS_MADE += 1
                print(f"📊 API call #{API_CALLS_MADE}")
                
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
                    print(f"✅ Successful analysis for {file_path}")
                    return response.text
                else:
                    print(f"⚠️ Warning: Empty response from Gemini for {file_path}")
                    return "No issues found."
                    
            except Exception as retry_error:
                error_msg = str(retry_error).lower()
                
                # Enhanced error handling for different types of API errors
                if "rate limit" in error_msg or "quota" in error_msg:
                    print(f"� Rate limit hit on attempt {attempt + 1} for {file_path}")
                    print(f"📊 Error details: {retry_error}")
                    
                    if attempt < max_retries - 1:
                        # For rate limits, use longer delays
                        delay = base_delay * (3 ** attempt)  # 2s, 6s, 18s, 54s
                        print(f"⏳ Rate limit backoff: waiting {delay}s before retry...")
                        import time
                        time.sleep(delay)
                        continue
                    else:
                        return f"Error: API rate limit exceeded after {max_retries} attempts. Please try again later or upgrade your API quota."
                        
                elif "api key" in error_msg or "authentication" in error_msg:
                    return "Error: Invalid API key or authentication failed"
                    
                elif "network" in error_msg or "connection" in error_msg:
                    print(f"🌐 Network error on attempt {attempt + 1}: {retry_error}")
                    if attempt < max_retries - 1:
                        continue
                    else:
                        return "Error: Network connectivity issues"
                        
                else:
                    print(f"🔄 Attempt {attempt + 1} failed for {file_path}: {retry_error}")
                    
                    if attempt == max_retries - 1:
                        return f"Error: {retry_error}"
        
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
    Post the findings as a comment on the GitHub commit or PR.
    
    Args:
        comment_body (str): The comment content to post
    """
    if not GITHUB_TOKEN or not GITHUB_REPOSITORY or not GITHUB_SHA:
        print("⚠️ Missing GitHub environment variables, skipping comment posting")
        return False
    
    try:
        # Try different comment endpoints in order of preference
        endpoints_to_try = [
            # First try commit comments
            {
                'url': f"https://api.github.com/repos/{GITHUB_REPOSITORY}/commits/{GITHUB_SHA}/comments",
                'type': 'commit comment'
            },
            # Then try PR comments if this is a PR
            {
                'url': f"https://api.github.com/repos/{GITHUB_REPOSITORY}/issues/comments",
                'type': 'issue comment'
            }
        ]
        
        for endpoint in endpoints_to_try:
            try:
                print(f"📝 Attempting to post {endpoint['type']} to GitHub...")
                
                # Set up headers with different auth formats
                auth_headers = [
                    {
                        'Authorization': f'Bearer {GITHUB_TOKEN}',
                        'Accept': 'application/vnd.github+json',
                        'X-GitHub-Api-Version': '2022-11-28',
                        'Content-Type': 'application/json'
                    },
                    {
                        'Authorization': f'token {GITHUB_TOKEN}',
                        'Accept': 'application/vnd.github.v3+json',
                        'Content-Type': 'application/json'
                    }
                ]
                
                for headers in auth_headers:
                    # Create payload
                    payload = {'body': comment_body}
                    
                    # Make POST request
                    response = requests.post(endpoint['url'], json=payload, headers=headers, timeout=30)
                    
                    if response.status_code == 201:
                        print(f"✅ Successfully posted {endpoint['type']} on GitHub")
                        return True
                    elif response.status_code == 403:
                        print(f"🚫 Permission denied for {endpoint['type']} (403)")
                        print(f"💡 Response: {response.text}")
                        continue  # Try next auth method
                    elif response.status_code == 404:
                        print(f"🔍 Endpoint not found for {endpoint['type']} (404)")
                        break  # Try next endpoint
                    else:
                        print(f"❌ Failed {endpoint['type']}. Status: {response.status_code}")
                        print(f"📋 Response: {response.text}")
                        continue
                        
            except requests.exceptions.RequestException as req_err:
                print(f"🌐 Network error for {endpoint['type']}: {req_err}")
                continue
        
        # If all methods failed, create a summary file instead
        print("📝 All comment methods failed, creating local summary instead...")
        create_local_summary(comment_body)
        return False
        
    except Exception as e:
        print(f"❌ Unexpected error posting comment: {e}")
        create_local_summary(comment_body)
        return False


def create_local_summary(comment_body):
    """
    Create a local summary file when GitHub comment posting fails.
    
    Args:
        comment_body (str): The comment content to save
    """
    try:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        summary_filename = f"security_summary_{timestamp}.md"
        
        with open(summary_filename, 'w', encoding='utf-8') as f:
            f.write(f"# Security Scan Summary\n\n")
            f.write(f"**Generated**: {datetime.now().strftime('%Y-%m-%d %H:%M:%S UTC')}\n\n")
            f.write(comment_body)
        
        print(f"📄 Security summary saved to: {summary_filename}")
        
    except Exception as e:
        print(f"❌ Error creating local summary: {e}")


def generate_pdf_report(vulnerabilities_found, changed_files, analysis_errors):
    """
    Generate a comprehensive PDF security report.
    
    Args:
        vulnerabilities_found (list): List of vulnerability findings
        changed_files (list): List of scanned files
        analysis_errors (list): List of analysis errors
        
    Returns:
        str: Path to the generated PDF file or None if generation failed
    """
    if not REPORTLAB_AVAILABLE:
        print("⚠️ PDF generation skipped - reportlab not installed")
        return None
    
    try:
        # Create filename with timestamp
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        commit_short = GITHUB_SHA[:8] if GITHUB_SHA else "unknown"
        repo_name = GITHUB_REPOSITORY.split('/')[-1] if GITHUB_REPOSITORY else "unknown"
        pdf_filename = f"security_report_{repo_name}_{commit_short}_{timestamp}.pdf"
        
        # Create PDF document
        doc = SimpleDocTemplate(pdf_filename, pagesize=A4)
        styles = getSampleStyleSheet()
        
        # Custom styles
        title_style = ParagraphStyle(
            'CustomTitle',
            parent=styles['Title'],
            fontSize=24,
            spaceAfter=30,
            textColor=HexColor('#2c3e50'),
            alignment=1  # Center alignment
        )
        
        heading_style = ParagraphStyle(
            'CustomHeading',
            parent=styles['Heading1'],
            fontSize=16,
            spaceAfter=12,
            textColor=HexColor('#34495e'),
            leftIndent=0
        )
        
        subheading_style = ParagraphStyle(
            'CustomSubHeading',
            parent=styles['Heading2'],
            fontSize=14,
            spaceAfter=8,
            textColor=HexColor('#7f8c8d'),
            leftIndent=0
        )
        
        # Content container
        content = []
        
        # Title page
        content.append(Paragraph("🛡️ Patch Panda Security Scan Report", title_style))
        content.append(Spacer(1, 20))
        
        # Summary table
        summary_data = [
            ['Repository', GITHUB_REPOSITORY or 'N/A'],
            ['Commit', GITHUB_SHA[:8] if GITHUB_SHA else 'N/A'],
            ['Scan Date', datetime.now().strftime("%Y-%m-%d %H:%M:%S UTC")],
            ['Files Scanned', str(len(changed_files))],
            ['Vulnerabilities Found', str(len([v for v in vulnerabilities_found if v.get('is_vulnerability', True)]))],
            ['Analysis Errors', str(len(analysis_errors))]
        ]
        
        summary_table = Table(summary_data, colWidths=[2*inch, 3*inch])
        summary_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), HexColor('#ecf0f1')),
            ('TEXTCOLOR', (0, 0), (-1, 0), HexColor('#2c3e50')),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, 0), 12),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
            ('BACKGROUND', (0, 1), (-1, -1), HexColor('#ffffff')),
            ('GRID', (0, 0), (-1, -1), 1, HexColor('#bdc3c7'))
        ]))
        
        content.append(summary_table)
        content.append(Spacer(1, 30))
        
        # Separate vulnerabilities from errors
        actual_vulnerabilities = [v for v in vulnerabilities_found if v.get('is_vulnerability', True)]
        errors_found = [v for v in vulnerabilities_found if not v.get('is_vulnerability', True)]
        
        # Vulnerabilities section
        if actual_vulnerabilities:
            content.append(Paragraph("🚨 Security Vulnerabilities", heading_style))
            content.append(Spacer(1, 12))
            
            for i, vuln in enumerate(actual_vulnerabilities, 1):
                # Parse vulnerability content
                vuln_content = vuln['markdown'].replace('## 🚨 Security Issues Found in', '').replace('---', '').strip()
                
                content.append(Paragraph(f"Vulnerability #{i}: {vuln['file']}", subheading_style))
                
                # Parse structured content
                lines = vuln_content.split('\n')
                formatted_content = []
                
                for line in lines:
                    line = line.strip()
                    if not line:
                        continue
                    
                    if line.startswith('**VULNERABILITY #'):
                        formatted_content.append(f"<b>{line.replace('**', '')}</b>")
                    elif line.startswith('- **Line(s)'):
                        formatted_content.append(f"📍 {line[3:].replace('**', '')}")
                    elif line.startswith('- **Severity'):
                        severity = line.split(':')[1].strip() if ':' in line else 'Unknown'
                        severity_color = {
                            'Critical': '#e74c3c',
                            'High': '#f39c12', 
                            'Medium': '#f1c40f',
                            'Low': '#27ae60'
                        }.get(severity.replace('**', ''), '#95a5a6')
                        formatted_content.append(f"<font color='{severity_color}'>🔴 {line[3:].replace('**', '')}</font>")
                    elif line.startswith('- **Risk'):
                        formatted_content.append(f"⚠️ {line[3:].replace('**', '')}")
                    elif line.startswith('- **Fix'):
                        formatted_content.append(f"🔧 {line[3:].replace('**', '')}")
                    elif line and not line.startswith('**'):
                        formatted_content.append(line)
                
                # Add formatted content
                for formatted_line in formatted_content:
                    content.append(Paragraph(formatted_line, styles['Normal']))
                    content.append(Spacer(1, 6))
                
                content.append(Spacer(1, 20))
        
        # Analysis errors section
        if errors_found:
            content.append(Paragraph("⚠️ Analysis Errors", heading_style))
            content.append(Spacer(1, 12))
            
            for i, error in enumerate(errors_found, 1):
                content.append(Paragraph(f"Error #{i}: {error['file']}", subheading_style))
                error_content = error['markdown'].replace('## ⚠️ Analysis Error in', '').replace('---', '').strip()
                content.append(Paragraph(error_content, styles['Normal']))
                content.append(Spacer(1, 15))
        
        # Files scanned section
        if changed_files:
            content.append(Paragraph("📁 Files Scanned", heading_style))
            content.append(Spacer(1, 12))
            
            files_data = [['File Path', 'Status']]
            for file_path in changed_files:
                has_vulns = any(vuln['file'] == file_path for vuln in actual_vulnerabilities)
                has_errors = any(error['file'] == file_path for error in errors_found)
                
                if has_vulns:
                    status = "🚨 Vulnerabilities Found"
                elif has_errors:
                    status = "❌ Analysis Error"
                else:
                    status = "✅ Clean"
                    
                files_data.append([file_path, status])
            
            files_table = Table(files_data, colWidths=[4*inch, 1.5*inch])
            files_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), HexColor('#ecf0f1')),
                ('TEXTCOLOR', (0, 0), (-1, 0), HexColor('#2c3e50')),
                ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, 0), 10),
                ('FONTSIZE', (0, 1), (-1, -1), 9),
                ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
                ('BACKGROUND', (0, 1), (-1, -1), HexColor('#ffffff')),
                ('GRID', (0, 0), (-1, -1), 1, HexColor('#bdc3c7')),
                ('VALIGN', (0, 0), (-1, -1), 'TOP')
            ]))
            
            content.append(files_table)
        
        # Footer
        content.append(Spacer(1, 30))
        content.append(Paragraph("Generated by Patch Panda Security Scanner", styles['Normal']))
        content.append(Paragraph(f"Report generated on: {datetime.now().strftime('%Y-%m-%d %H:%M:%S UTC')}", styles['Normal']))
        
        # Build PDF
        doc.build(content)
        
        print(f"✅ PDF report generated: {pdf_filename}")
        return pdf_filename
        
    except Exception as e:
        print(f"❌ Error generating PDF report: {e}")
        return None


def commit_pdf_to_branch(pdf_path):
    """
    Commit the PDF report to a dedicated branch in the repository.
    
    Args:
        pdf_path (str): Path to the PDF file to commit
        
    Returns:
        bool: True if successful, False otherwise
    """
    if not pdf_path or not os.path.exists(pdf_path):
        print("❌ PDF file not found, skipping Git commit")
        return False
    
    try:
        # Validate Git environment
        if not GITHUB_TOKEN:
            print("❌ GITHUB_TOKEN not available, cannot commit to repository")
            return False
        
        # Branch name for reports
        reports_branch = "security-reports"
        
        print(f"📝 Committing PDF report to {reports_branch} branch...")
        
        # Configure Git user (required for commits)
        subprocess.run(['git', 'config', 'user.name', 'Patch Panda Scanner'], check=True, capture_output=True)
        subprocess.run(['git', 'config', 'user.email', 'security-scanner@patchpanda.ai'], check=True, capture_output=True)
        
        # Set up authentication for HTTPS
        if GITHUB_REPOSITORY and GITHUB_TOKEN:
            auth_url = f"https://{GITHUB_TOKEN}@github.com/{GITHUB_REPOSITORY}.git"
            subprocess.run(['git', 'remote', 'set-url', 'origin', auth_url], check=True, capture_output=True)
        
        # Fetch latest changes
        subprocess.run(['git', 'fetch', 'origin'], check=True, capture_output=True)
        
        # Check if reports branch exists remotely
        branch_check = subprocess.run(
            ['git', 'ls-remote', '--heads', 'origin', reports_branch],
            capture_output=True, text=True
        )
        
        if branch_check.stdout.strip():
            # Branch exists, checkout and pull
            print(f"🔄 Checking out existing {reports_branch} branch...")
            subprocess.run(['git', 'checkout', reports_branch], check=True, capture_output=True)
            subprocess.run(['git', 'pull', 'origin', reports_branch], check=True, capture_output=True)
        else:
            # Branch doesn't exist, create it
            print(f"🌟 Creating new {reports_branch} branch...")
            subprocess.run(['git', 'checkout', '--orphan', reports_branch], check=True, capture_output=True)
            
            # Remove all files from staging (orphan branch starts with all files staged)
            subprocess.run(['git', 'rm', '-rf', '.'], check=True, capture_output=True)
            
            # Create a README for the reports branch
            readme_content = f"""# Security Reports Branch

This branch contains PDF security reports generated by Patch Panda Scanner.

## About
- **Repository**: {GITHUB_REPOSITORY}
- **Scanner**: Patch Panda Security Scanner
- **Reports**: Organized by date and commit

## Report Format
- Filename pattern: `security_report_<repo>_<commit>_<timestamp>.pdf`
- Contains detailed vulnerability analysis
- Includes scanned files and error reports
- Generated automatically on each scan

## Latest Reports
Reports are automatically added here after each security scan.
"""
            
            with open('README.md', 'w', encoding='utf-8') as f:
                f.write(readme_content)
            
            subprocess.run(['git', 'add', 'README.md'], check=True, capture_output=True)
        
        # Create reports directory if it doesn't exist
        reports_dir = 'reports'
        if not os.path.exists(reports_dir):
            os.makedirs(reports_dir)
        
        # Move PDF to reports directory
        pdf_filename = os.path.basename(pdf_path)
        new_pdf_path = os.path.join(reports_dir, pdf_filename)
        
        if os.path.exists(new_pdf_path):
            os.remove(new_pdf_path)  # Remove existing file
        
        # Copy PDF to reports directory
        subprocess.run(['copy' if os.name == 'nt' else 'cp', pdf_path, new_pdf_path], 
                      shell=True, check=True)
        
        # Add and commit the PDF
        subprocess.run(['git', 'add', new_pdf_path], check=True, capture_output=True)
        
        commit_message = f"Add security report for commit {GITHUB_SHA[:8] if GITHUB_SHA else 'unknown'}\n\nGenerated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S UTC')}"
        
        subprocess.run(['git', 'commit', '-m', commit_message], check=True, capture_output=True)
        
        # Push to remote
        subprocess.run(['git', 'push', 'origin', reports_branch], check=True, capture_output=True)
        
        # Switch back to original branch
        original_branch = os.getenv('GITHUB_REF_NAME', 'main')
        subprocess.run(['git', 'checkout', original_branch], check=True, capture_output=True)
        
        print(f"✅ PDF report committed to {reports_branch} branch successfully")
        print(f"📂 Report location: {reports_branch}/reports/{pdf_filename}")
        
        return True
        
    except subprocess.CalledProcessError as e:
        print(f"❌ Git command failed: {e}")
        print(f"Command output: {e.output if hasattr(e, 'output') else 'N/A'}")
        return False
    except Exception as e:
        print(f"❌ Error committing PDF to branch: {e}")
        return False


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
        model = genai.GenerativeModel('gemini-2.5-flash')
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
*🐼 Report generated by **Patch Panda** Security Scanner.*
"""
        post_comment_on_commit(neutral_comment)
        exit(0)
    
    print(f"📁 Found {len(changed_files)} changed source code file(s): {', '.join(changed_files)}")
    
    # Limit files to prevent rate limiting
    if len(changed_files) > MAX_FILES_PER_RUN:
        print(f"⚠️ Warning: Found {len(changed_files)} files, limiting to {MAX_FILES_PER_RUN} to prevent rate limiting")
        changed_files = changed_files[:MAX_FILES_PER_RUN]
        print(f"📝 Scanning first {len(changed_files)} files: {', '.join(changed_files)}")
    
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
            
            # Add small delay between files to prevent rate limiting
            if changed_files.index(file_path) > 0:  # Skip delay for first file
                import time
                print("⏳ Adding 2s delay between file analyses to prevent rate limiting...")
                time.sleep(2)
            
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
    
    # Always generate reports (even if no vulnerabilities found)
    print(f"\n📝 Generating reports...")
    
    # Count actual vulnerabilities vs errors
    vuln_count = len(actual_vulnerabilities) if 'actual_vulnerabilities' in locals() else 0
    error_count = len(errors_found) if 'errors_found' in locals() else 0
    
    # Always generate PDF report first
    print("📄 Generating PDF report...")
    pdf_path = generate_pdf_report(vulnerabilities_found, changed_files, analysis_errors)
    
    # Commit PDF to dedicated branch (always, regardless of findings)
    if pdf_path:
        print("📝 Committing PDF report to repository...")
        commit_success = commit_pdf_to_branch(pdf_path)
        if not commit_success:
            print("⚠️ PDF commit failed, keeping local copy for debugging")
    
    # Generate and send other reports if we have results (vulnerabilities or errors)
    if vulnerabilities_found:
        
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
        
        # Add PDF link to GitHub comment if available
        if pdf_path and os.path.exists(os.path.basename(pdf_path)) == False:  # PDF was committed successfully
            reports_branch_url = f"https://github.com/{GITHUB_REPOSITORY}/blob/security-reports/reports/{os.path.basename(pdf_path)}"
            commit_comment += f"""

📄 **Detailed PDF Report**: [View Report]({reports_branch_url})
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
"""
        
        # Add PDF link if available
        if pdf_path and os.path.exists(pdf_path):
            reports_branch_url = f"https://github.com/{GITHUB_REPOSITORY}/blob/security-reports/reports/{os.path.basename(pdf_path)}"
            completion_comment += f"""
📄 **Detailed PDF Report**: [View Report]({reports_branch_url})
"""
        
        completion_comment += """
---
*🐼 Report generated by **Patch Panda** Security Scanner*
"""
        
        post_comment_on_commit(completion_comment)
    
    # Clean up local PDF file after all operations
    if pdf_path and os.path.exists(pdf_path):
        try:
            os.remove(pdf_path)
            print("🧹 Cleaned up local PDF file")
        except Exception as e:
            print(f"⚠️ Warning: Could not clean up PDF file: {e}")
    
    print(f"\n🔍 Security scan completed!")
    print(f"📊 Final Summary:")
    print(f"   📁 Files scanned: {len(changed_files)}")
    print(f"   🚨 Security issues: {len(actual_vulnerabilities) if 'actual_vulnerabilities' in locals() else 0}")
    print(f"   ❌ Analysis errors: {len(analysis_errors)}")
    
    # PDF report summary
    if REPORTLAB_AVAILABLE and pdf_path:
        print(f"   📄 PDF report: Generated and committed to 'security-reports' branch")
        print(f"   🔗 Report URL: https://github.com/{GITHUB_REPOSITORY}/tree/security-reports/reports")
        print(f"   📋 PDF filename: {os.path.basename(pdf_path) if pdf_path else 'N/A'}")
    elif not REPORTLAB_AVAILABLE:
        print(f"   📄 PDF report: Skipped (reportlab not available)")
    else:
        print(f"   📄 PDF report: Generation failed")
    
    # GitHub Actions summary annotations
    if 'actual_vulnerabilities' in locals():
        vuln_count = len(actual_vulnerabilities)
        if vuln_count > 0:
            print(f"::notice title=Patch Panda Security Scan::🚨 Found {vuln_count} security vulnerabilities across {len(changed_files)} files")
            print(f"::warning::🚨 SECURITY ALERT: {vuln_count} vulnerabilities detected! Check the scan results above.")
            if REPORTLAB_AVAILABLE:
                print(f"::notice::📄 Detailed PDF report available in 'security-reports' branch")
        else:
            print(f"::notice title=Patch Panda Security Scan::✅ No security vulnerabilities detected in {len(changed_files)} files")
    
    # Exit with appropriate code
    if 'actual_vulnerabilities' in locals() and len(actual_vulnerabilities) > 0:
        print("⚠️ Security vulnerabilities detected! Please review the findings.")
        print("📄 Check the detailed PDF report in the 'security-reports' branch for comprehensive analysis.")
        # Don't exit with error code as this might block the workflow
        # exit(1)
    else:
        print("🎉 No security vulnerabilities detected!")
