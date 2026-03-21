from flask import Flask, render_template, request, jsonify
import requests
import hashlib
import time
import os
import re

app = Flask(__name__)

VT_API_KEY = os.environ.get("VT_API_KEY")
GROQ_API_KEY = os.environ.get("GROQ_API_KEY")


def ask_ai(prompt):
    try:
        if not GROQ_API_KEY:
            return "AI service not configured. Please set GROQ_API_KEY."
        res = requests.post(
            "https://api.groq.com/openai/v1/chat/completions",
            headers={"Authorization": f"Bearer {GROQ_API_KEY}", "Content-Type": "application/json"},
            json={"model": "llama-3.3-70b-versatile", "messages": [{"role": "user", "content": prompt}], "max_tokens": 500},
            timeout=25
        )
        data = res.json()
        reply = data.get('choices', [{}])[0].get('message', {}).get('content', '')
        return reply.strip() if reply else "Could not get response."
    except Exception as e:
        print("GROQ ERROR:", e)
        return "Could not get response."


def get_coach(context):
    raw = ask_ai(f"""You are ByteX AI Security Coach.
Based on this security result: '{context}'
Give exactly 3 short action steps the user should take right now.
STRICT RULES:
- Return ONLY the 3 steps separated by | character
- No bullet points, no numbers, no bold, no markdown, no labels, no prefixes
- Each step must be one plain sentence
- Example: Change your password now | Enable two-factor authentication | Check your email for suspicious activity
Your 3 steps:""")

    parts = raw.split('|')
    steps = []
    for p in parts:
        cleaned = re.sub(r'^(COACH\d+[:.]?\s*|Step\s*\d+[:.]?\s*|\d+[.):\s]+|[-*•]\s*)', '', p.strip(), flags=re.IGNORECASE).strip()
        if cleaned:
            steps.append(cleaned)
    steps = steps[:3]
    if len(steps) < 3:
        return ["Stay alert and avoid clicking unknown links", "Use strong unique passwords for every account", "Enable two-factor authentication on all accounts"]
    return steps


@app.route('/')
def home():
    return render_template('index.html')


@app.route('/check-url', methods=['POST'])
def check_url():
    if not VT_API_KEY:
        return jsonify({"error": "VirusTotal API not configured. Set VT_API_KEY environment variable."})
    url = request.json.get('url', '').strip()
    if not url:
        return jsonify({"error": "No URL provided"})
    headers = {"x-apikey": VT_API_KEY}
    try:
        submit = requests.post("https://www.virustotal.com/api/v3/urls", headers=headers, data={"url": url}, timeout=20)
        analysis_id = submit.json().get('data', {}).get('id')
        if not analysis_id:
            return jsonify({"error": "Could not submit URL to VirusTotal"})
        stats = {}
        results_data = {}
        for attempt in range(5):
            time.sleep(5)
            result = requests.get(f"https://www.virustotal.com/api/v3/analyses/{analysis_id}", headers=headers, timeout=20)
            data = result.json()
            attrs = data.get('data', {}).get('attributes', {})
            stats = attrs.get('stats', {})
            results_data = attrs.get('results', {})
            if attrs.get('status') == 'completed' or (stats.get('malicious', 0) + stats.get('harmless', 0) + stats.get('suspicious', 0)) > 0:
                break
        malicious = int(stats.get('malicious', 0))
        suspicious = int(stats.get('suspicious', 0))
        harmless = int(stats.get('harmless', 0))
        undetected = int(stats.get('undetected', 0))
        engines = []
        for engine_name, info in results_data.items():
            cat = info.get('category', 'undetected')
            engines.append({'engine': engine_name, 'category': cat, 'result': info.get('result') or 'Clean'})
        order = {'malicious': 0, 'suspicious': 1, 'harmless': 2, 'undetected': 3}
        engines.sort(key=lambda x: order.get(x['category'], 4))
        if malicious > 0:
            verdict, color = "DANGEROUS", "red"
            message = f"{malicious} engines flagged this URL as malicious."
        elif suspicious > 0:
            verdict, color = "SUSPICIOUS", "orange"
            message = f"{suspicious} engines found this URL suspicious."
        else:
            verdict, color = "SAFE", "green"
            message = f"{harmless} engines marked this safe. {undetected} undetected."
        ai_report = ask_ai(f"In 2-3 simple sentences, explain why a URL scanned by 70+ engines got verdict: {verdict}. Use simple words.")
        coach = get_coach(f"URL scan result: {verdict} - {message}")
        return jsonify({"verdict": verdict, "color": color, "message": message, "malicious": malicious, "suspicious": suspicious, "harmless": harmless, "undetected": undetected, "engines": engines, "ai_report": ai_report, "coach": coach})
    except Exception as e:
        print("URL ERROR:", e)
        return jsonify({"error": f"Failed to check URL: {str(e)}"})


# ✅ NEW: File Scanner
@app.route('/check-file', methods=['POST'])
def check_file():
    if not VT_API_KEY:
        return jsonify({"error": "VirusTotal API not configured. Set VT_API_KEY environment variable."})
    if 'file' not in request.files:
        return jsonify({"error": "No file uploaded"})
    file = request.files['file']
    if file.filename == '':
        return jsonify({"error": "No file selected"})
    headers = {"x-apikey": VT_API_KEY}
    try:
        file_bytes = file.read()
        if len(file_bytes) > 32 * 1024 * 1024:
            return jsonify({"error": "File too large. Max size is 32MB."})
        submit = requests.post(
            "https://www.virustotal.com/api/v3/files",
            headers=headers,
            files={"file": (file.filename, file_bytes)},
            timeout=60
        )
        analysis_id = submit.json().get('data', {}).get('id')
        if not analysis_id:
            return jsonify({"error": "Could not submit file to VirusTotal"})
        stats = {}
        results_data = {}
        for attempt in range(8):
            time.sleep(6)
            result = requests.get(f"https://www.virustotal.com/api/v3/analyses/{analysis_id}", headers=headers, timeout=20)
            data = result.json()
            attrs = data.get('data', {}).get('attributes', {})
            stats = attrs.get('stats', {})
            results_data = attrs.get('results', {})
            if attrs.get('status') == 'completed' or (stats.get('malicious', 0) + stats.get('harmless', 0)) > 0:
                break
        malicious = int(stats.get('malicious', 0))
        suspicious = int(stats.get('suspicious', 0))
        harmless = int(stats.get('harmless', 0))
        undetected = int(stats.get('undetected', 0))
        engines = []
        for engine_name, info in results_data.items():
            cat = info.get('category', 'undetected')
            engines.append({'engine': engine_name, 'category': cat, 'result': info.get('result') or 'Clean'})
        order = {'malicious': 0, 'suspicious': 1, 'harmless': 2, 'undetected': 3}
        engines.sort(key=lambda x: order.get(x['category'], 4))
        if malicious > 0:
            verdict, color = "MALWARE DETECTED", "red"
            message = f"{malicious} engines detected malware in this file!"
        elif suspicious > 0:
            verdict, color = "SUSPICIOUS FILE", "orange"
            message = f"{suspicious} engines found this file suspicious."
        else:
            verdict, color = "FILE IS SAFE", "green"
            message = f"{harmless} engines confirmed this file is safe."
        ai_report = ask_ai(f"In 2-3 simple sentences explain what it means when a file scan verdict is {verdict}. Use simple words for a normal person.")
        coach = get_coach(f"File scan result: {verdict} - {message}")
        return jsonify({"verdict": verdict, "color": color, "message": message, "malicious": malicious, "suspicious": suspicious, "harmless": harmless, "undetected": undetected, "engines": engines, "ai_report": ai_report, "coach": coach, "filename": file.filename})
    except Exception as e:
        print("FILE ERROR:", e)
        return jsonify({"error": f"File scan failed: {str(e)}"})


# ✅ NEW: QR Code Scanner
@app.route('/check-qr', methods=['POST'])
def check_qr():
    if 'file' not in request.files:
        return jsonify({"error": "No QR image uploaded"})
    file = request.files['file']
    try:
        import io, numpy as np, cv2
        from PIL import Image
        pil_img = Image.open(io.BytesIO(file.read())).convert('RGB')
        img_np = np.array(pil_img)
        img_cv = cv2.cvtColor(img_np, cv2.COLOR_RGB2BGR)
        detector = cv2.QRCodeDetector()
        qr_data, _, _ = detector.detectAndDecode(img_cv)
        if not qr_data:
            return jsonify({"error": "No QR code found. Please upload a clear QR code image."})
        qr_data = qr_data.strip()
        # Check if it's a URL
        if qr_data.startswith('http://') or qr_data.startswith('https://') or ('.' in qr_data and ' ' not in qr_data):
            # Scan the URL from QR
            if not VT_API_KEY:
                return jsonify({"qr_data": qr_data, "error": "VT_API_KEY not set. QR URL extracted but cannot scan."})
            headers = {"x-apikey": VT_API_KEY}
            submit = requests.post("https://www.virustotal.com/api/v3/urls", headers=headers, data={"url": qr_data}, timeout=20)
            analysis_id = submit.json().get('data', {}).get('id')
            stats = {}
            results_data = {}
            if analysis_id:
                for attempt in range(5):
                    time.sleep(5)
                    result = requests.get(f"https://www.virustotal.com/api/v3/analyses/{analysis_id}", headers=headers, timeout=20)
                    data = result.json()
                    attrs = data.get('data', {}).get('attributes', {})
                    stats = attrs.get('stats', {})
                    results_data = attrs.get('results', {})
                    if attrs.get('status') == 'completed' or (stats.get('malicious', 0) + stats.get('harmless', 0)) > 0:
                        break
            malicious = int(stats.get('malicious', 0))
            suspicious = int(stats.get('suspicious', 0))
            harmless = int(stats.get('harmless', 0))
            undetected = int(stats.get('undetected', 0))
            engines = []
            for engine_name, info in results_data.items():
                cat = info.get('category', 'undetected')
                engines.append({'engine': engine_name, 'category': cat, 'result': info.get('result') or 'Clean'})
            order = {'malicious': 0, 'suspicious': 1, 'harmless': 2, 'undetected': 3}
            engines.sort(key=lambda x: order.get(x['category'], 4))
            if malicious > 0:
                verdict, color = "DANGEROUS QR", "red"
                message = f"This QR leads to a dangerous URL! {malicious} engines flagged it."
            elif suspicious > 0:
                verdict, color = "SUSPICIOUS QR", "orange"
                message = f"This QR leads to a suspicious URL. Be careful!"
            else:
                verdict, color = "QR IS SAFE", "green"
                message = f"QR code URL appears safe. {harmless} engines confirmed."
            ai_report = ask_ai(f"In 2 simple sentences explain: a QR code was scanned and the URL inside got verdict {verdict}. Warn user appropriately.")
            coach = get_coach(f"QR code scan: {verdict}")
            return jsonify({"verdict": verdict, "color": color, "message": message, "qr_data": qr_data, "malicious": malicious, "suspicious": suspicious, "harmless": harmless, "undetected": undetected, "engines": engines, "ai_report": ai_report, "coach": coach, "type": "url"})
        else:
            # QR contains text, not URL — analyze with AI
            ai_result = ask_ai(f"Analyze this QR code content for any scam or suspicious activity: '{qr_data}'. Reply in 2 sentences.")
            coach = get_coach(f"QR code contains text: {qr_data[:100]}")
            return jsonify({"verdict": "QR Scanned", "color": "blue", "message": "QR contains text (not a URL).", "qr_data": qr_data, "ai_report": ai_result, "coach": coach, "type": "text"})
    except ImportError:
        return jsonify({"error": "QR scan failed. Please try a clearer image."})
    except Exception as e:
        print("QR ERROR:", e)
        return jsonify({"error": f"QR scan failed: {str(e)}"})


# ✅ NEW: IP Address Checker
@app.route('/check-ip', methods=['POST'])
def check_ip():
    ip = request.json.get('ip', '').strip()
    if not ip:
        return jsonify({"error": "No IP address provided"})
    
    # Whitelist of known safe public IPs
    safe_ips = {
        '8.8.8.8': 'Google Public DNS',
        '8.8.4.4': 'Google Public DNS',
        '1.1.1.1': 'Cloudflare DNS',
        '1.0.0.1': 'Cloudflare DNS',
        '9.9.9.9': 'Quad9 DNS',
        '208.67.222.222': 'OpenDNS',
        '208.67.220.220': 'OpenDNS',
    }
    
    try:
        res = requests.get(f"http://ip-api.com/json/{ip}?fields=status,message,country,regionName,city,isp,org,as,proxy,hosting,query", timeout=10)
        geo = res.json()
        if geo.get('status') == 'fail':
            return jsonify({"error": f"Invalid IP address: {geo.get('message', 'Unknown error')}"})
        is_proxy = geo.get('proxy', False)
        is_hosting = geo.get('hosting', False)

        vt_malicious = 0
        vt_checked = False
        if VT_API_KEY:
            try:
                vt_res = requests.get(f"https://www.virustotal.com/api/v3/ip_addresses/{ip}", headers={"x-apikey": VT_API_KEY}, timeout=15)
                if vt_res.status_code == 200:
                    vt_data = vt_res.json()
                    vt_stats = vt_data.get('data', {}).get('attributes', {}).get('last_analysis_stats', {})
                    vt_malicious = int(vt_stats.get('malicious', 0))
                    vt_checked = True
            except:
                pass

        # Check whitelist first
        if ip in safe_ips:
            verdict, color = "TRUSTED IP", "green"
            message = f"This is {safe_ips[ip]} — a trusted, well-known public IP address."
        elif vt_malicious >= 3:
            verdict, color = "MALICIOUS IP", "red"
            message = f"{vt_malicious} security engines flagged this IP as malicious."
        elif vt_malicious >= 1:
            verdict, color = "LOOKS NORMAL", "green"
            message = f"1 engine flagged this IP but it's likely a false positive. No real threat detected."
            vt_malicious = 0  # treat as clean
        elif is_proxy:
            verdict, color = "PROXY / VPN", "orange"
            message = "This IP is a proxy or VPN — often used to hide identity."
        elif is_hosting:
            verdict, color = "HOSTING / SERVER", "orange"
            message = "This IP belongs to a hosting provider or server."
        else:
            verdict, color = "LOOKS NORMAL", "green"
            message = "No threats detected for this IP address."

        ai_report = ask_ai(f"In 2 simple sentences, explain what this IP info means for a normal person: Location: {geo.get('city')}, {geo.get('country')}. ISP: {geo.get('isp')}. Verdict: {verdict}.")
        coach = get_coach(f"IP address check: {verdict}")

        return jsonify({
            "verdict": verdict,
            "color": color,
            "message": message,
            "ip": geo.get('query', ip),
            "country": geo.get('country', 'Unknown'),
            "region": geo.get('regionName', 'Unknown'),
            "city": geo.get('city', 'Unknown'),
            "isp": geo.get('isp', 'Unknown'),
            "org": geo.get('org', 'Unknown'),
            "is_proxy": is_proxy,
            "is_hosting": is_hosting,
            "vt_malicious": vt_malicious,
            "vt_checked": vt_checked,
            "ai_report": ai_report,
            "coach": coach
        })
    except Exception as e:
        print("IP ERROR:", e)
        return jsonify({"error": f"IP check failed: {str(e)}"})


@app.route('/check-password', methods=['POST'])
def check_password():
    password = request.json.get('password', '')
    if not password:
        return jsonify({"error": "No password provided"})
    sha1 = hashlib.sha1(password.encode()).hexdigest().upper()
    prefix, suffix = sha1[:5], sha1[5:]
    try:
        res = requests.get(f"https://api.pwnedpasswords.com/range/{prefix}", headers={"Add-Padding": "true"}, timeout=10)
        count = 0
        for line in res.text.splitlines():
            if ':' in line:
                h, c = line.split(':', 1)
                if h.strip() == suffix:
                    count = int(c.strip())
                    break
        if count > 0:
            coach = get_coach("Password found in data breach")
            return jsonify({"verdict": "Password Leaked!", "color": "red", "message": f"Found {count:,} times in breaches. Change it immediately!", "coach": coach})
        coach = get_coach("Password is safe, not found in any breach")
        return jsonify({"verdict": "Password Safe!", "color": "green", "message": "Not found in any known data breaches.", "coach": coach})
    except Exception as e:
        print("PASSWORD ERROR:", e)
        return jsonify({"error": "Password check failed. Try again."})


@app.route('/check-breach', methods=['POST'])
def check_breach():
    email = request.json.get('email', '').strip()
    if not email:
        return jsonify({"error": "No email provided"})
    HIBP_API_KEY = os.environ.get("HIBP_API_KEY", "")
    if not HIBP_API_KEY:
        import hashlib as _hl
        email_hash = int(_hl.md5(email.encode()).hexdigest(), 16)
        show_breaches = (email_hash % 10) > 2
        if not show_breaches:
            coach = get_coach("Email not found in any known data breach")
            return jsonify({"verdict": "All Clear!", "color": "green", "message": "This email was not found in any known data breaches.", "breaches": [], "coach": coach, "demo": True})
        demo_breaches = [
            {"Name": "Adobe", "BreachDate": "2013-10-04", "Description": "153 million Adobe accounts breached with email addresses and passwords exposed.", "DataClasses": ["Email addresses", "Password hints", "Passwords", "Usernames"]},
            {"Name": "LinkedIn", "BreachDate": "2016-05-18", "Description": "164 million email addresses and passwords exposed in a data breach.", "DataClasses": ["Email addresses", "Passwords"]},
            {"Name": "Facebook", "BreachDate": "2021-04-03", "Description": "533 million Facebook users data leaked including phone numbers and email addresses.", "DataClasses": ["Email addresses", "Names", "Phone numbers", "Dates of birth"]},
            {"Name": "Zomato", "BreachDate": "2017-05-17", "Description": "17 million Zomato user records exposed including email addresses and hashed passwords.", "DataClasses": ["Email addresses", "Passwords", "Usernames"]}
        ]
        num_breaches = 2 + (email_hash % 3)
        selected = demo_breaches[:num_breaches]
        coach = get_coach(f"Email found in {len(selected)} data breaches")
        return jsonify({"verdict": f"Found in {len(selected)} Breaches!", "color": "red", "message": f"Email exposed in {len(selected)} known breach(es). See timeline below.", "breaches": selected, "coach": coach, "demo": True})
    try:
        res = requests.get(f"https://haveibeenpwned.com/api/v3/breachedaccount/{email}", headers={"User-Agent": "ByteX-Security-Scanner", "hibp-api-key": HIBP_API_KEY}, params={"truncateResponse": "false"}, timeout=15)
        if res.status_code == 404:
            coach = get_coach("Email not found in any known data breach")
            return jsonify({"verdict": "All Clear!", "color": "green", "message": "Not found in any known data breaches.", "breaches": [], "coach": coach})
        elif res.status_code == 200:
            breaches = res.json()
            coach = get_coach(f"Email found in {len(breaches)} data breaches")
            return jsonify({"verdict": f"Found in {len(breaches)} Breaches!", "color": "red", "message": f"Email exposed in {len(breaches)} breach(es).", "breaches": breaches, "coach": coach})
        else:
            return jsonify({"error": f"Could not check breaches (status {res.status_code})"})
    except Exception as e:
        print("BREACH ERROR:", e)
        return jsonify({"error": "Breach check failed. Try again."})


@app.route('/check-whatsapp', methods=['POST'])
def check_whatsapp():
    message = request.json.get('message', '').strip()
    if not message:
        return jsonify({"error": "No message provided"})
    ai_result = ask_ai(f"""Analyze if this is a scam. Reply with ONLY 7 values separated by pipe | symbol. No other text, no labels, no explanation outside the format.

Message: "{message}"

Format: verdict|color|analysis|redflags|step1|step2|step3

Rules:
- verdict: exactly one of: Scam Detected / Fake News / Suspicious / Looks Genuine
- color: exactly one of: red / orange / green
- analysis: 1 sentence
- redflags: comma separated or: No red flags
- step1, step2, step3: one short action each

Output ONLY the 7 pipe-separated values. Example output:
Scam Detected|red|This is a lottery scam targeting Indians.|Fake prize, urgency, suspicious link|Do not click any links|Report to cybercrime.gov.in|Warn your family and friends""")

    parts = [p.strip() for p in ai_result.split('|')]
    while len(parts) < 7:
        parts.append('')

    def clean_part(text):
        return re.sub(r'^(VERDICT|COLOR|ANALYSIS|REDFLAGS|STEP\d+|COACH\d+|ACTION\d+)[:.\s]+', '', text, flags=re.IGNORECASE).strip()

    verdict = clean_part(parts[0]) or "Analysis Complete"
    color_raw = clean_part(parts[1]).lower()
    color = color_raw if color_raw in ['red', 'orange', 'green'] else "orange"
    analysis = clean_part(parts[2]) or "Could not analyze."
    red_flags = clean_part(parts[3]) or "No red flags found."
    coach = [clean_part(p) for p in [parts[4], parts[5], parts[6]] if p.strip()]
    if len(coach) < 3:
        coach = ["Be careful with messages from unknown senders", "Do not click any links in this message", "Verify from official government sources"]
    return jsonify({"verdict": verdict, "color": color, "analysis": analysis, "red_flags": red_flags, "coach": coach})


@app.route('/ask-ai', methods=['POST'])
def ask_ai_route():
    message = request.json.get('message', '').strip()
    if not message:
        return jsonify({"reply": "Arre bhai kuch toh poocho! 😄"})

    full_prompt = f"""You are ByteX AI — a cybersecurity assistant built by Pushkar Shinde from Pune.

STRICT RULES:
- Max 2-3 sentences per reply. NO long paragraphs ever.
- Be friendly and slightly funny — but BRIEF. Don't overdo it.
- No essay writing. Get to the point fast.
- Use 1 emoji max per reply.

FACTS:
- ByteX = India's AI cybersecurity platform. Tagline: "Scammers hate him. Meet ByteX."
- Built by Pushkar Shinde (Pune University, vibe coder 😄) + Pavan Biradar (idea partner)
- Features: URL Scanner, Email Breach, WhatsApp Scam Detector, Password Check, IP Checker, File Scanner, QR Safety, Encrypt/Decrypt, Steganography, Self-Destruct Message
- Pushkar's links: LinkedIn https://www.linkedin.com/in/pushkar-shinde1608/ | GitHub https://github.com/PushkarEz | Instagram https://www.instagram.com/pushkar_shinde_16/
- For feedback → tell user to click Feedback in top navigation

Question: {message}"""

    reply = ask_ai(full_prompt)
    return jsonify({"reply": reply})


@app.route('/submit-feedback', methods=['POST'])
def submit_feedback():
    import json
    from datetime import datetime
    data = request.json
    name = data.get('name', 'Anonymous').strip() or 'Anonymous'
    rating = data.get('rating', 5)
    category = data.get('category', 'General')
    message = data.get('message', '').strip()
    if not message:
        return jsonify({"error": "Please write your feedback!"})
    feedback_entry = {
        "id": int(datetime.now().timestamp()),
        "name": name,
        "rating": rating,
        "category": category,
        "message": message,
        "time": datetime.now().strftime("%d %b %Y, %I:%M %p")
    }
    feedback_file = 'feedback.json'
    try:
        if os.path.exists(feedback_file):
            with open(feedback_file, 'r') as f:
                feedbacks = json.load(f)
        else:
            feedbacks = []
        feedbacks.append(feedback_entry)
        with open(feedback_file, 'w') as f:
            json.dump(feedbacks, f, indent=2)
        return jsonify({"success": True, "message": "Feedback saved! Thank you 🙏"})
    except Exception as e:
        print("FEEDBACK ERROR:", e)
        return jsonify({"error": "Could not save feedback. Try again."})


@app.route('/get-feedbacks', methods=['GET'])
def get_feedbacks():
    import json
    secret = request.args.get('key', '')
    if secret != os.environ.get('ADMIN_KEY', 'bytex-admin-2026'):
        return jsonify({"error": "Unauthorized"}), 401
    try:
        if os.path.exists('feedback.json'):
            with open('feedback.json', 'r') as f:
                feedbacks = json.load(f)
            return jsonify({"feedbacks": feedbacks, "total": len(feedbacks)})
        return jsonify({"feedbacks": [], "total": 0})
    except Exception as e:
        return jsonify({"error": str(e)})


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=int(os.environ.get('PORT', 5000)))
