# 🛠️ Patch Panda Troubleshooting Guide

## Common Issues and Solutions

### ❌ "Error occurred during analysis"

This error indicates problems with the Gemini API call. Here are the fixes applied:

#### **Root Causes:**
1. **Outdated model name**: Changed from `gemini-pro` to `gemini-1.5-flash`
2. **Missing safety settings**: Added safety settings to prevent blocking
3. **No retry logic**: Added exponential backoff retry mechanism
4. **Large files**: Added content truncation for files over 30KB
5. **Poor error handling**: Improved error messages and debugging

#### **Fixes Applied:**
✅ Updated to `gemini-1.5-flash` model
✅ Added content size limits and truncation
✅ Implemented retry logic with exponential backoff
✅ Added safety settings to prevent content blocking
✅ Enhanced error messages with specific failure reasons
✅ Added API connection testing at startup

### 🔧 **Testing Your Setup Locally**

Use the new test script to debug issues:

```bash
# Test a single file locally
python test_scanner.py "test files/test.py"

# Or run interactively
python test_scanner.py
```

### 🔍 **Common Error Messages**

| Error | Cause | Solution |
|-------|-------|----------|
| `Error: Invalid or missing API key` | Wrong/missing Gemini API key | Check your `GEMINI_API_KEY` secret |
| `Error: API rate limit exceeded` | Too many requests | Wait a few minutes, reduce file sizes |
| `Error: Content too large for analysis` | File too big | Files are now auto-truncated at 30KB |
| `Gemini API connection failed` | Network/API issues | Check internet connection and API key |

### 📊 **Improved Features**

#### **Better Error Handling**
- Specific error messages for different failure types
- Retry logic for transient failures
- Graceful handling of large files

#### **Enhanced Reporting**
- Errors now appear in both GitHub comments and email reports
- Better formatting with color coding
- File size and encoding information

#### **Validation & Testing**
- API connection tested at startup
- File existence and size validation
- Multiple encoding support (UTF-8, Latin-1, CP1252)

### 🚀 **Next Steps**

1. **Push the updated code** to your repository
2. **Test with small files first** to verify the fixes
3. **Check GitHub Actions logs** for detailed error information
4. **Use the local test script** to debug specific files

### 📝 **Updated Workflow**

The scanner now:
1. ✅ Tests API connection before scanning
2. ✅ Validates file size and encoding
3. ✅ Retries failed requests automatically
4. ✅ Provides detailed error reporting
5. ✅ Handles edge cases gracefully

### 🔧 **Manual Testing Commands**

```bash
# Test API connection
python -c "import google.generativeai as genai; genai.configure(api_key='YOUR_KEY'); print('✅ API works')"

# Test file reading
python test_scanner.py "test files/test.py"

# Check file sizes
ls -la "test files/"
```

Your Patch Panda scanner should now work reliably! 🛡️🐼