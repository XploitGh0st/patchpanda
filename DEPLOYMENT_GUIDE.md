# 🛡️ Patch Panda Security Scanner Deployment Guide

## 📋 Overview
Patch Panda is an automated security scanner that analyzes code changes in your GitHub repository using AI-powered vulnerability detection. It runs on every push and pull request to keep your code secure.

## 🚀 Quick Setup

### 1. Add the Scanner to Your Repository

1. **Copy the files:**
   - Copy `scan.py` to your repository root
   - Copy `.github/workflows/security-scan.yml` to your repository

2. **Commit and push:**
   ```bash
   git add scan.py .github/workflows/security-scan.yml
   git commit -m "🛡️ Add Patch Panda security scanner"
   git push
   ```

### 2. Configure Required Secrets

Go to your GitHub repository → **Settings** → **Secrets and variables** → **Actions** → **New repository secret**

#### Required Secrets:
- **`GEMINI_API_KEY`** - Your Google AI API key (see setup below)

#### Optional Secrets (for email reports):
- **`GMAIL_APP_PASSWORD`** - Gmail app-specific password
- **`REPORT_EMAIL_FROM`** - Gmail address to send from
- **`REPORT_EMAIL_TO`** - Email address to receive reports

## 🔑 Setting Up Google Gemini API

### Step 1: Get a Gemini API Key
1. Go to [Google AI Studio](https://makersuite.google.com/app/apikey)
2. Sign in with your Google account
3. Click **"Create API Key"**
4. Copy the generated API key

### Step 2: Add to GitHub Secrets
1. In your GitHub repo: **Settings** → **Secrets and variables** → **Actions**
2. Click **"New repository secret"**
3. Name: `GEMINI_API_KEY`
4. Value: Paste your API key
5. Click **"Add secret"**

## 📧 Setting Up Gmail Notifications (Optional)

### Step 1: Enable 2-Factor Authentication
1. Go to your Google Account settings
2. Enable 2-Factor Authentication if not already enabled

### Step 2: Generate App Password
1. Go to [Google Account Security](https://myaccount.google.com/security)
2. Under "Signing in to Google" → **App passwords**
3. Select **Mail** and your device
4. Copy the 16-character password generated

### Step 3: Add Gmail Secrets
Add these three secrets to your GitHub repository:

- **`GMAIL_APP_PASSWORD`** - The 16-character app password
- **`REPORT_EMAIL_FROM`** - Your Gmail address (e.g., yourname@gmail.com)
- **`REPORT_EMAIL_TO`** - Email where reports should be sent

## 🔧 Configuration Options

### Trigger Events
The scanner runs on:
- **Push to main/develop branches**
- **Pull requests to main branch**

### Supported Languages
- Python (`.py`)
- JavaScript (`.js`)
- TypeScript (`.ts`)
- Java (`.java`)
- C# (`.cs`)
- Go (`.go`)
- Ruby (`.rb`)
- PHP (`.php`)
- Rust (`.rs`)
- C/C++ (`.c`, `.cpp`, `.h`)
- HTML (`.html`)
- CSS (`.css`)

### Customizing Triggers
Edit `.github/workflows/security-scan.yml` to change when scans run:

```yaml
on:
  push:
    branches: [ main, develop, staging ]  # Add more branches
  pull_request:
    branches: [ main ]
  schedule:
    - cron: '0 2 * * 1'  # Weekly scan on Mondays at 2 AM
```

## 📊 Understanding Results

### GitHub Comments
- **Green ✅**: No vulnerabilities found
- **Red 🚨**: Security issues detected
- **Details**: Line numbers, explanations, and fix suggestions

### Email Reports
- **HTML formatted** with professional styling
- **Direct links** to the commit
- **Detailed breakdown** of each vulnerability
- **Fix recommendations** for each issue

## 🛠️ Advanced Configuration

### Custom File Extensions
Edit `scan.py` to add support for more file types:

```python
CODE_FILE_EXTENSIONS = ['.py', '.js', '.ts', '.java', '.cs', '.go', '.rb',
                       '.php', '.rs', '.c', '.cpp', '.h', '.html', '.css',
                       '.kt', '.swift', '.scala']  # Add Kotlin, Swift, Scala
```

### Custom Analysis Prompt
Modify the prompt in `analyze_code_with_gemini()` to focus on specific vulnerability types or add custom rules.

### Workflow Permissions
The workflow requires these permissions:
- `contents: read` - To access repository files
- `issues: write` - To post comments (if needed)
- `pull-requests: write` - To comment on PRs

## 🚨 Security Best Practices

1. **Never commit API keys** - Always use GitHub Secrets
2. **Rotate API keys regularly** - Update secrets periodically
3. **Use app passwords** - Never use your main Gmail password
4. **Review scan results** - Don't ignore security warnings
5. **Test in development** - Verify setup on feature branches first

## 📈 Monitoring & Maintenance

### Check Workflow Status
- Go to **Actions** tab in your GitHub repository
- Monitor scan results and any failures
- Check the logs if scans fail

### API Usage Limits
- **Gemini API**: Check your usage at [Google AI Studio](https://makersuite.google.com/)
- **GitHub API**: 5000 requests per hour for authenticated requests

### Updating Dependencies
Keep the scanner updated by occasionally updating the Python dependencies:

```yaml
- name: 📦 Install dependencies
  run: |
    python -m pip install --upgrade pip
    pip install --upgrade google-generativeai requests
```

## 🐛 Troubleshooting

### Common Issues

1. **"GEMINI_API_KEY not found"**
   - Verify the secret is added correctly
   - Check the secret name matches exactly

2. **"No changed files found"**
   - Ensure you have at least 2 commits in your repository
   - Check if the changed files have supported extensions

3. **Email not sending**
   - Verify all three Gmail secrets are set
   - Check that 2FA is enabled on your Google account
   - Ensure the app password is correct

4. **Permission denied errors**
   - Check workflow permissions in the YAML file
   - Verify GitHub token has necessary scopes

### Debug Mode
Add debug output by modifying the scanner:

```python
import logging
logging.basicConfig(level=logging.DEBUG)
```

## 📞 Support

For issues or questions:
1. Check the GitHub Actions logs
2. Verify all secrets are configured correctly
3. Test with a simple code change first
4. Review the console output for error messages

## 🎯 Next Steps

1. **Test the setup** - Make a small code change and push
2. **Review first scan** - Check the GitHub comment and email
3. **Customize settings** - Adjust triggers and file types as needed
4. **Monitor regularly** - Keep an eye on scan results and act on findings

---

**🐼 Happy scanning with Patch Panda!** Your repository is now protected by AI-powered security analysis.