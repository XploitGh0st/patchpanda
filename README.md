# 🛡️ Patch Panda Security Scanner

An AI-powered security scanner for GitHub repositories that automatically detects vulnerabilities in code changes using Google's Gemini API.

## 🚀 Quick Start

1. **Add to your repository:**
   ```bash
   # Copy scan.py and .github/workflows/security-scan.yml to your repo
   git add scan.py .github/workflows/security-scan.yml
   git commit -m "🛡️ Add Patch Panda security scanner"
   git push
   ```

2. **Set up API key:**
   - Get a [Gemini API key](https://makersuite.google.com/app/apikey)
   - Add it as `GEMINI_API_KEY` in GitHub repository secrets

3. **Push code changes** and watch Patch Panda automatically scan for vulnerabilities!

## ✨ Features

- 🔍 **Smart Detection**: Analyzes only changed files in commits
- 🌐 **Multi-language**: Supports 14 programming languages
- 🤖 **AI-Powered**: Uses Google Gemini for intelligent vulnerability detection
- 📝 **Dual Reporting**: GitHub comments + email notifications
- ⚡ **Fast**: Runs automatically on every push and PR
- 🛡️ **Comprehensive**: Detects SQL injection, XSS, command injection, and more

## 🔧 Setup

See [DEPLOYMENT_GUIDE.md](DEPLOYMENT_GUIDE.md) for complete setup instructions.

### Required Secrets
- `GEMINI_API_KEY` - Your Google AI API key

### Optional Secrets (for email reports)
- `GMAIL_APP_PASSWORD` - Gmail app password
- `REPORT_EMAIL_FROM` - Sender email
- `REPORT_EMAIL_TO` - Recipient email

## 📊 Supported Languages

- Python, JavaScript, TypeScript
- Java, C#, Go, Ruby, PHP, Rust
- C/C++, HTML, CSS

## 🛡️ Security Checks

- SQL Injection
- Cross-Site Scripting (XSS)
- Command Injection
- Insecure Deserialization
- Path Traversal
- Hardcoded Secrets
- Memory Safety Issues
- Race Conditions

## 📈 Example Output

### GitHub Comment
```
🛡️ Patch Panda Security Scan Report

Commit: a1b2c3d4
Repository: owner/repo
Files Scanned: 3
Vulnerabilities Found: 1

🚨 Security Issues Found in src/app.py
- SQL Injection vulnerability on line 42
- Recommendation: Use parameterized queries
```

### Email Report
Professional HTML report with detailed findings, fix suggestions, and direct links to the commit.

## 🐛 Troubleshooting

1. **API key issues**: Verify `GEMINI_API_KEY` is set correctly
2. **No files scanned**: Ensure changed files have supported extensions
3. **Email not sending**: Check Gmail app password and 2FA settings

## 📝 License

MIT License - see [LICENSE](LICENSE) file for details.

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests if applicable
5. Submit a pull request

---

**🐼 Protect your code with Patch Panda!**