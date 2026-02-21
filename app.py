from flask import Flask, request, jsonify, sendfile, send_from_directory
from flask_cors import CORS
import subprocess
import re
import ssl
import socket
import requests
from datetime import datetime
import io
import logging
import traceback
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.lib import colors
from reportlab.lib.units import inch

app = Flask(__name__)
CORS(app)
logging.basicConfig(level=logging.INFO)

# ============== HOME ==============
@app.route('/')
def home():
    return send_from_directory('.', 'index.html')

# ============== VALIDATION ==============
def validate_domain(domain):
    pattern = r'^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)*[a-zA-Z]{2,}$'
    return re.match(pattern, domain) is not None

# ============== SSL CHECK ==============
def check_ssl(hostname):
    try:
        hostname = hostname.replace('https://', '').replace('http://', '').split('/')[0]
        context = ssl.create_default_context()
        with socket.create_connection((hostname, 443), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                expiry_date = datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
                remaining_days = (expiry_date - datetime.utcnow()).days
                if remaining_days < 0:
                    status = 'Expired'
                elif remaining_days < 30:
                    status = 'Expiring Soon'
                else:
                    status = 'Valid'
                return status, expiry_date.strftime('%Y-%m-%d'), remaining_days
    except Exception:
        logging.debug('SSL check failed: %s', traceback.format_exc())
        return 'No SSL', 'N/A', 0

# ============== HEADER CHECK ==============
def analyze_headers(domain):
    findings = []
    recommendations = []
    strengths = []
    try:
        response = requests.get(f'https://{domain}', timeout=5)
        headers = response.headers
        if 'Strict-Transport-Security' not in headers:
            findings.append('HSTS header not configured.')
            recommendations.append('Enable HSTS to enforce HTTPS.')
        else:
            strengths.append('HSTS header properly configured.')
        if 'Content-Security-Policy' not in headers:
            findings.append('Content-Security-Policy header missing.')
            recommendations.append('Configure CSP to prevent XSS attacks.')
        else:
            strengths.append('Content-Security-Policy implemented.')
    except:
        findings.append('Unable to analyze HTTP headers.')
    return findings, recommendations, strengths

# ============== GEO IP ==============
def get_geoip(domain):
    try:
        ip = socket.gethostbyname(domain)
        res = requests.get(f'http://ip-api.com/json/{ip}').json()
        return ip, res.get('country', 'Unknown')
    except:
        logging.debug('Geo IP lookup failed: %s', traceback.format_exc())
        return 'Unknown', 'Unknown'

# ============== AI RISK ENGINE ==============
def air_risk_analysis(domain, ports, ssl_status, header_findings, header_strengths):
    score = 100
    vulnerabilities = []
    recommendations = []
    strengths = list(header_strengths)
    piracy_keywords = ['movierulz', 'torrent', 'pirate', '123movies']
    if any(word in domain.lower() for word in piracy_keywords):
        score -= 70
        vulnerabilities.append('Domain associated with piracy/illegal streaming.')
        recommendations.append('Avoid accessing unverified piracy platforms.')
    if ssl_status == 'No SSL':
        score -= 60
        vulnerabilities.append('No SSL certificate detected.')
        recommendations.append('Enable HTTPS with valid SSL certificate.')
    elif ssl_status == 'Expired':
        score -= 50
        vulnerabilities.append('SSL certificate expired.')
        recommendations.append('Renew SSL certificate immediately.')
    else:
        strengths.append('Valid SSL certificate detected.')
    if 21 in ports:
        score -= 25
        vulnerabilities.append('Unsecured FTP Port 21 open.')
        recommendations.append('Disable FTP or switch to secure SFTP.')
    if 23 in ports:
        score -= 40
        vulnerabilities.append('Telnet Port 23 open.')
        recommendations.append('Disable Telnet and use SSH instead.')
    for issue in header_findings:
        score -= 10
        vulnerabilities.append(issue)
    score = max(0, min(score, 100))
    if score < 30:
        risk = 'HIGH'
    elif score < 70:
        risk = 'MEDIUM'
    else:
        risk = 'LOW'
    if not vulnerabilities:
        strengths.append('No critical vulnerabilities detected.')
    return score, risk, vulnerabilities, recommendations, strengths

# ============== SCAN ROUTE ==============
@app.route('/scan', methods=['POST'])
def scan():
    raw = request.json.get('url')
    domain = raw.replace('https://', '').replace('http://', '').split('/')[0]
    if not validate_domain(domain):
        return jsonify({'error': 'Invalid domain'}), 400
    
    open_ports = []
    try:
        res = subprocess.check_output(['nmap', '-Pn', '-T4', '-p', '21,23,80,443', domain], stderr=subprocess.STDOUT, text=True)
        open_ports = re.findall(r'(\d+)/tcp open', res)
    except FileNotFoundError:
        logging.info('nmap not found, falling back to simple port connect scan')
    except subprocess.CalledProcessError:
        logging.info('nmap failed, falling back to simple port connect scan')
    except Exception:
        logging.debug('nmap scan exception: %s', traceback.format_exc())
    
    if not open_ports:
        common_ports = [21, 23, 80, 443]
        for p in common_ports:
            try:
                with socket.create_connection((domain, p), timeout=1):
                    open_ports.append(str(p))
            except:
                continue
    
    ssl_status, expiry, days = check_ssl(domain)
    header_findings, header_recs, header_strengths = analyze_headers(domain)
    geo = get_geoip(domain)
    score, risk, vulnerabilities, recommendations, strengths = air_risk_analysis(domain, open_ports, ssl_status, header_findings, header_strengths)
    recommendations.extend(header_recs)
    
    return jsonify(
        target=domain,
        open_ports=open_ports,
        ssl_status=ssl_status,
        expiry=expiry,
        days=days,
        score=score,
        risk=risk,
        vulnerabilities=vulnerabilities,
        recommendations=recommendations,
        strengths=strengths,
        geoip=geo
    )

# ============== PDF REPORT ==============
@app.route('/download-report', methods=['POST'])
def download_report():
    data = request.json or {}
    filename = 'SecurityAuditReport.pdf'
    styles = getSampleStyleSheet()
    elements = []
    elements.append(Paragraph('<font size=18 color=blue><b>PenTest AI - Security Audit Report</b></font>', styles['Normal']))
    elements.append(Spacer(1, 0.3 * inch))
    elements.append(Paragraph(f"<b>Target Domain:</b> {data.get('target', 'N/A')}", styles['Normal']))
    elements.append(Paragraph(f"<b>Audit Timestamp:</b> {datetime.now().strftime('%Y-%m-%d %H:%M')}", styles['Normal']))
    elements.append(Spacer(1, 0.3 * inch))
    
    table_data = [
        ['Risk Assessment', data.get('risk', 'N/A')],
        ['AI Security Score', f"{data.get('score', 'N/A')}"],
        ['SSL Status', data.get('ssl_status', 'N/A')],
        ['Certificate Expiry', data.get('expiry', 'N/A')],
        ['Days Remaining', f"{data.get('days', 'N/A')} Days"],
        ['Open Ports', ', '.join(data.get('open_ports', [])) if data.get('open_ports') else 'None']
    ]
    table = Table(table_data, colWidths=[2.5 * inch, 3.5 * inch])
    table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.blue),
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
        ('GRID', (0, 0), (-1, -1), 0.5, colors.grey)
    ]))
    elements.append(table)
    elements.append(Spacer(1, 0.4 * inch))
    elements.append(Paragraph('<b>Vulnerabilities</b>', styles['Heading2']))
    for v in data.get('vulnerabilities', []):
        elements.append(Paragraph(f'{v}', styles['Normal']))
    elements.append(Spacer(1, 0.3 * inch))
    elements.append(Paragraph('<b>Security Recommendations</b>', styles['Heading2']))
    for r in data.get('recommendations', []):
        elements.append(Paragraph(f'{r}', styles['Normal']))
    elements.append(Spacer(1, 0.3 * inch))
    elements.append(Paragraph('<b>Strengths</b>', styles['Heading2']))
    for s in data.get('strengths', []):
        elements.append(Paragraph(f'{s}', styles['Normal']))
    
    buffer = io.BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=(8.5 * inch, 11 * inch))
    doc.build(elements)
    buffer.seek(0)
    try:
        return send_file(buffer, as_attachment=True, download_name=filename, mimetype='application/pdf')
    except TypeError:
        return send_file(buffer, as_attachment=True, attachment_filename=filename, mimetype='application/pdf')

if __name__ == '__main__':
    app.run(debug=True)
