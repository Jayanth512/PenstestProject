# PenTest AI - Automated Pentesting Dashboard

Lightweight Flask app that performs basic active checks (port scan fallback), SSL expiry, header analysis, geo lookup and produces a PDF security report.

**Important**: This tool performs network scanning. Only run scans against assets you own or are explicitly authorized to test.

## Quick Start

1. Create a Python virtual environment and activate it.
   ```bash
   python -m venv .venv
   # Windows
   .venv\Scripts\activate
   # Unix
   source .venv/bin/activate
   ```

2. Install dependencies
   ```bash
   pip install -r requirements.txt
   ```

3. Run the app locally
   ```bash
   python app.py
   ```
   Open http://127.0.0.1:5000

## Features

- **Domain Validation**: Ensures valid domain input
- **SSL Certificate Analysis**: Checks SSL status and expiry dates
- **Port Scanning**: Detects open ports (21, 23, 80, 443) with nmap fallback
- **Header Analysis**: Scans for HSTS and Content-Security-Policy headers
- **Geo IP Lookup**: Identifies server location
- **Risk Assessment**: AI-powered vulnerability scoring
- **PDF Report Generation**: Creates comprehensive security audit reports

## Notes and Improvements

- Added health endpoint for readiness checks
- Safer handling if nmap is not available - TCP connect fallback
- PDF generation streams from memory - no temp files left behind
- Basic input size limit and improved error handling
- Frontend now handles scan errors and disables PDF until a scan completes

## Security Ethics

- This project can be used to scan remote systems - ensure you have permission
- Unauthorized scanning can be illegal
- Consider adding authentication, rate-limiting, and auditing before exposing this service

## Suggested Next Steps

- Add authentication (API key/OAuth) to scan and download/report endpoints
- Move long-running scans to a background job queue (Redis/Celery or RQ)
- Add logging to persistent storage and a simple UI audit trail
- Improve header analysis and expand port coverage
- Add tests and CI (not included per project request)

## Running Tests

Run the included unit tests using Python's unittest:
```bash
python -m unittest discover -v
```

## Files of Interest

- `app.py` - Main Flask app and analysis logic
- `index.html` - UI with Tailwind CSS
- `requirements.txt` - Dependencies
- `tests` - Unit tests

---
Created for a final project review - modify as needed# PenstestProject
Lightweight Flask app for automated pentesting with SSL checks, port scanning, header analysis, and PDF report generation.
