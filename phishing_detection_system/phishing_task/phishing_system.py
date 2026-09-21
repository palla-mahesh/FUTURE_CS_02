import re
import json
import os
import io
from datetime import datetime
from email import policy
from email.parser import BytesParser
from email.utils import parseaddr
from urllib.parse import urlparse
from bs4 import BeautifulSoup
from fastapi import FastAPI, UploadFile, File, Request, HTTPException
from fastapi.responses import HTMLResponse, StreamingResponse
from jinja2 import Template
import uvicorn

class PhishingAnalyzer:
    def __init__(self):
        self.suspicious_keywords = [
            "urgent", "verify", "account suspended", "click here", "password",
            "bank", "login", "update", "immediately", "ssn", "social security",
            "wire transfer", "invoice", "payment", "confirm", "security alert",
            "unauthorized", "restricted", "limited time", "act now"
        ]
        self.trusted_brands = [
            "paypal", "google", "microsoft", "apple", "amazon", "netflix",
            "bankofamerica", "chase", "wellsfargo", "facebook", "instagram"
        ]
        self.shortener_domains = ["bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd"]
        self.dangerous_extensions = [".exe", ".scr", ".vbs", ".js", ".jar", ".bat", ".cmd", ".ps1", ".hta"]

    def _extract_urls(self, html_content):
        soup = BeautifulSoup(html_content, "html.parser")
        links = []
        for a in soup.find_all('a', href=True):
            links.append({"href": a['href'], "text": a.get_text(strip=True)})
        return links

    def _check_url_anomalies(self, url):
        indicators = []
        try:
            parsed = urlparse(url)
            domain = parsed.netloc.lower()
            if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', domain):
                indicators.append({"type": "Raw IP Address", "detail": f"URL uses raw IP ({domain}).", "severity": "High"})
            for shortener in self.shortener_domains:
                if shortener in domain:
                    indicators.append({"type": "URL Shortener", "detail": f"URL uses shortener ({domain}).", "severity": "Medium"})
            if "xn--" in domain:
                indicators.append({"type": "Punycode Detected", "detail": f"Domain '{domain}' uses Punycode.", "severity": "High"})
            return indicators, domain
        except Exception:
            return [], ""

    def analyze_email(self, raw_email_bytes, filename="unknown.eml"):
        try:
            msg = BytesParser(policy=policy.default).parsebytes(raw_email_bytes)
        except Exception as e:
            return {"filename": filename, "classification": "Error", "color": "danger", "score": 0,
                    "sender": "N/A", "reply_to": "", "subject": "Parse Error", "date": "N/A",
                    "attachments": [], "indicators": [{"type": "Parse Error", "detail": str(e), "severity": "Critical"}],
                    "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")}

        sender_header = msg['from'] or ""
        reply_to_header = msg['reply-to'] or ""
        subject = msg['subject'] or "No Subject"
        date = msg['date'] or "Unknown Date"
        body_text, body_html, attachments = "", "", []

        if msg.is_multipart():
            for part in msg.walk():
                content_type = part.get_content_type()
                content_disposition = str(part.get("Content-Disposition"))
                if "attachment" in content_disposition:
                    fn = part.get_filename()
                    if fn: attachments.append(fn)
                elif content_type == "text/plain":
                    try: body_text += part.get_payload(decode=True).decode(errors='ignore')
                    except: pass
                elif content_type == "text/html":
                    try: body_html += part.get_payload(decode=True).decode(errors='ignore')
                    except: pass
        else:
            ct = msg.get_content_type()
            if ct == "text/plain": body_text = msg.get_payload(decode=True).decode(errors='ignore')
            elif ct == "text/html": body_html = msg.get_payload(decode=True).decode(errors='ignore')

        full_body = body_text + " " + body_html
        score, indicators = 0, []

        sender_name, sender_email = parseaddr(sender_header)
        sender_domain = sender_email.split('@')[-1].lower() if '@' in sender_email else ""
        if sender_name:
            for brand in self.trusted_brands:
                if brand.lower() in sender_name.lower() and brand.lower() not in sender_domain:
                    score += 25
                    indicators.append({"type": "Display Name Spoofing", "detail": f"Name '{sender_name}' mentions '{brand}' but domain is '{sender_domain}'.", "severity": "High"})

        if reply_to_header:
            _, reply_email = parseaddr(reply_to_header)
            reply_domain = reply_email.split('@')[-1].lower() if '@' in reply_email else ""
            if reply_domain and reply_domain != sender_domain:
                score += 15
                indicators.append({"type": "Reply-To Mismatch", "detail": f"Reply-To ({reply_domain}) differs from Sender ({sender_domain}).", "severity": "Medium"})

        found_keywords = [w for w in self.suspicious_keywords if w.lower() in subject.lower() or w.lower() in full_body.lower()]
        if found_keywords:
            score += min(len(found_keywords) * 5, 30)
            indicators.append({"type": "Suspicious Keywords", "detail": f"Found: {', '.join(found_keywords)}", "severity": "Medium"})

        urls = self._extract_urls(body_html) if body_html else []
        for link in urls:
            url_inds, domain = self._check_url_anomalies(link['href'])
            for ind in url_inds:
                score += 15
                indicators.append(ind)
            if link['text'] and link['text'].startswith("http"):
                text_domain = urlparse(link['text']).netloc
                if text_domain and domain and text_domain != domain:
                    score += 20
                    indicators.append({"type": "Mismatched Link", "detail": f"Text shows '{text_domain}' but goes to '{domain}'.", "severity": "High"})

        for att in attachments:
            ext = os.path.splitext(att)[1].lower()
            if ext in self.dangerous_extensions:
                score += 40
                indicators.append({"type": "Dangerous Attachment", "detail": f"Attachment '{att}' has high-risk extension ({ext}).", "severity": "Critical"})

        if len(msg.get_all('received', [])) < 1:
            score += 10
            indicators.append({"type": "Missing Header Info", "detail": "No 'Received' headers found.", "severity": "Medium"})

        score = min(score, 100)
        if score >= 60: classification, color = "Phishing", "danger"
        elif score >= 25: classification, color = "Suspicious", "warning"
        else: classification, color = "Safe", "success"

        unique_indicators, seen = [], set()
        for ind in indicators:
            identifier = f"{ind['type']}-{ind['detail']}"
            if identifier not in seen:
                seen.add(identifier)
                unique_indicators.append(ind)

        return {"filename": filename, "classification": classification, "color": color, "score": score,
                "sender": sender_header, "reply_to": reply_to_header, "subject": subject, "date": date,
                "attachments": attachments, "indicators": unique_indicators,
                "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")}

app = FastAPI(title="Phishing Email Detection & Awareness System")
analyzer = PhishingAnalyzer()

HTML_TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Phishing Detection & Awareness System</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css">
    <style>
        body { background-color: #0f172a; color: #e2e8f0; font-family: 'Segoe UI', sans-serif; }
        .card { background-color: #1e293b; border: 1px solid #334155; border-radius: 12px; }
        .header-title { color: #38bdf8; font-weight: 700; }
        .upload-area { border: 2px dashed #475569; border-radius: 10px; padding: 40px; text-align: center; cursor: pointer; transition: 0.3s; }
        .upload-area:hover { border-color: #38bdf8; background-color: #1e293b; }
        .result-safe { border-left: 5px solid #22c55e; }
        .result-suspicious { border-left: 5px solid #eab308; }
        .result-phishing { border-left: 5px solid #ef4444; }
        .indicator-card { background-color: #0f172a; border: 1px solid #334155; border-radius: 8px; margin-bottom: 10px; padding: 15px; }
        .badge-high { background-color: #ef4444; color: white; }
        .badge-medium { background-color: #eab308; color: #000; }
        .badge-critical { background-color: #7f1d1d; color: white; }
        .score-circle { width: 80px; height: 80px; border-radius: 50%; display: flex; align-items: center; justify-content: center; font-size: 24px; font-weight: bold; margin: 0 auto; }
    </style>
</head>
<body>
    <div class="container mt-5">
        <div class="text-center mb-5">
            <h1 class="header-title"><i class="fas fa-shield-alt"></i> Phishing Detection & Awareness System</h1>
            <p class="text-muted">Upload an email file (.eml) to analyze.</p>
        </div>
        <div class="row justify-content-center">
            <div class="col-md-8">
                <div class="card p-4">
                    <form action="/analyze" method="post" enctype="multipart/form-data">
                        <div class="upload-area" onclick="document.getElementById('fileInput').click()">
                            <i class="fas fa-cloud-upload-alt fa-3x mb-3" style="color: #38bdf8;"></i>
                            <h5>Click to Upload or Drag & Drop</h5>
                            <input type="file" id="fileInput" name="file" accept=".eml" style="display: none;" required onchange="document.getElementById('fileNameDisplay').textContent='Selected: '+this.files[0].name">
                        </div>
                        <div id="fileNameDisplay" class="mt-3 text-center text-info"></div>
                        <button type="submit" class="btn btn-primary w-100 mt-3" style="background-color: #38bdf8; border: none; color: #0f172a; font-weight: bold;">Analyze Email</button>
                    </form>
                </div>
            </div>
        </div>
        {% if result %}
        <div class="row justify-content-center mt-5">
            <div class="col-md-10">
                <div class="card p-4 result-{{ result.color }}">
                    <div class="row align-items-center">
                        <div class="col-md-3 text-center">
                            <div class="score-circle bg-{{ result.color }} text-white">{{ result.score }}</div>
                            <h5 class="mt-2 text-{{ result.color }}">{{ result.classification }}</h5>
                        </div>
                        <div class="col-md-9">
                            <p><strong>Subject:</strong> {{ result.subject }}</p>
                            <p><strong>From:</strong> {{ result.sender }}</p>
                            {% if result.reply_to %}<p class="text-warning"><strong>Reply-To:</strong> {{ result.reply_to }}</p>{% endif %}
                            <p><strong>Date:</strong> {{ result.date }}</p>
                        </div>
                    </div>
                    <hr style="border-color: #475569;">
                    <h5>Detected Indicators ({{ result.indicators|length }})</h5>
                    {% for ind in result.indicators %}
                    <div class="indicator-card">
                        <div class="d-flex justify-content-between">
                            <h6 class="text-info">{{ ind.type }}</h6>
                            <span class="badge badge-{{ ind.severity.lower() }}">{{ ind.severity }}</span>
                        </div>
                        <p class="mb-0">{{ ind.detail }}</p>
                    </div>
                    {% endfor %}
                    <div class="mt-4 text-center">
                        <a href="/download_report" class="btn btn-outline-info">Download JSON Report</a>
                    </div>
                </div>
            </div>
        </div>
        {% endif %}
    </div>
</body>
</html>
"""

last_analysis_result = {}

@app.get("/", response_class=HTMLResponse)
async def home(request: Request):
    return HTMLResponse(content=HTML_TEMPLATE)

@app.post("/analyze", response_class=HTMLResponse)
async def analyze_email(request: Request, file: UploadFile = File(...)):
    global last_analysis_result
    if not file.filename.endswith('.eml'):
        raise HTTPException(status_code=400, detail="Only .eml files supported.")
    contents = await file.read()
    result = analyzer.analyze_email(contents, file.filename)
    last_analysis_result = result
    return HTMLResponse(content=Template(HTML_TEMPLATE).render(result=result))

@app.get("/download_report")
async def download_report():
    global last_analysis_result
    if not last_analysis_result:
        raise HTTPException(status_code=404, detail="No report available.")
    json_str = json.dumps(last_analysis_result, indent=4)
    return StreamingResponse(io.BytesIO(json_str.encode()), media_type="application/json",
        headers={"Content-Disposition": f"attachment; filename=phishing_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"})

if __name__ == "__main__":
    print("=" * 60)
    print("  PHISHING DETECTION & AWARENESS SYSTEM")
    print("  Running on: http://0.0.0.0:8000")
    print("=" * 60)
    uvicorn.run(app, host="0.0.0.0", port=8000)
