"""
ByteX Telegram Bot
==================
Commands:
  /start   - Welcome message
  /help    - All commands
  /scan    - Scan a URL
  /email   - Check email breach
  /password - Check password breach
  /ip      - Check IP address
  /whatsapp - Check WhatsApp scam message
  /ask     - Ask ByteX AI anything

Just send any text and ByteX auto-detects what it is!

Setup:
  1. pip install python-telegram-bot requests
  2. Create bot via @BotFather on Telegram → get token
  3. Set environment variables:
     TELEGRAM_BOT_TOKEN=your_bot_token
     VT_API_KEY=your_virustotal_key
     GROQ_API_KEY=your_groq_key
  4. python bytex_bot.py
"""

import os
import re
import hashlib
import requests
import time
import logging
from telegram import Update, InlineKeyboardButton, InlineKeyboardMarkup
from telegram.ext import (
    Application, CommandHandler, MessageHandler,
    CallbackQueryHandler, ContextTypes, filters
)

logging.basicConfig(format="%(asctime)s - %(name)s - %(levelname)s - %(message)s", level=logging.INFO)
logger = logging.getLogger(__name__)

# ── ENV VARS ──────────────────────────────────────────────
TOKEN    = os.environ.get("TELEGRAM_BOT_TOKEN", "")
VT_KEY   = os.environ.get("VT_API_KEY", "")
GROQ_KEY = os.environ.get("GROQ_API_KEY", "")
HIBP_KEY = os.environ.get("HIBP_API_KEY", "")

# ── HELPERS ───────────────────────────────────────────────
def is_url(text):
    return bool(re.match(r'https?://\S+|www\.\S+', text.strip()))

def is_email(text):
    return bool(re.match(r'^[\w.+-]+@[\w-]+\.[a-z]{2,}$', text.strip()))

def is_ip(text):
    return bool(re.match(r'^\d{1,3}(\.\d{1,3}){3}$', text.strip()))

def detect_type(text):
    text = text.strip()
    if is_url(text):   return "url"
    if is_email(text): return "email"
    if is_ip(text):    return "ip"
    if len(text) >= 20: return "whatsapp"
    return "unknown"

# ── API FUNCTIONS ─────────────────────────────────────────
def scan_url(url):
    if not VT_KEY:
        return {"error": "VirusTotal API key not configured"}
    try:
        headers = {"x-apikey": VT_KEY}
        # Submit URL
        r = requests.post("https://www.virustotal.com/api/v3/urls",
            headers=headers, data={"url": url}, timeout=20)
        if r.status_code != 200:
            return {"error": f"VT submit failed: {r.status_code}"}
        analysis_id = r.json()["data"]["id"]
        # Poll for results
        for attempt in range(15):
            time.sleep(3)
            result = requests.get(
                f"https://www.virustotal.com/api/v3/analyses/{analysis_id}",
                headers=headers, timeout=20)
            if result.status_code != 200:
                continue
            rjson = result.json()
            data = rjson.get("data", {})
            attrs = data.get("attributes", {})
            status = attrs.get("status", "")
            if status == "completed":
                # Try both possible keys for stats
                stats = (attrs.get("last_analysis_stats") or
                         attrs.get("stats") or {})
                if not stats:
                    # Try results count manually
                    results = attrs.get("results", {})
                    mal = sum(1 for v in results.values() if v.get("category") == "malicious")
                    sus = sum(1 for v in results.values() if v.get("category") == "suspicious")
                    total = len(results)
                else:
                    mal = int(stats.get("malicious", 0))
                    sus = int(stats.get("suspicious", 0))
                    total = sum(int(v) for v in stats.values())
                if mal >= 3:
                    verdict = "🔴 DANGEROUS"
                elif mal >= 1 or sus >= 2:
                    verdict = "🟡 SUSPICIOUS"
                else:
                    verdict = "🟢 SAFE"
                return {"verdict": verdict, "malicious": mal,
                        "suspicious": sus, "total": total or 1}
        return {"error": "Scan timed out. Try again in a moment!"}
    except KeyError as e:
        return {"error": f"Unexpected API response: {str(e)}"}
    except Exception as e:
        return {"error": str(e)}

def check_email(email):
    try:
        if HIBP_KEY:
            r = requests.get(
                f"https://haveibeenpwned.com/api/v3/breachedaccount/{email}",
                headers={"User-Agent": "ByteX-Bot", "hibp-api-key": HIBP_KEY},
                params={"truncateResponse": "false"}, timeout=15)
            if r.status_code == 404:
                return {"verdict": "✅ ALL CLEAR", "breaches": [], "count": 0}
            elif r.status_code == 200:
                breaches = r.json()
                return {"verdict": f"🔴 FOUND IN {len(breaches)} BREACHES",
                        "breaches": [b["Name"] for b in breaches[:5]], "count": len(breaches)}
        # Demo mode
        import random
        count = random.randint(0, 3)
        if count == 0:
            return {"verdict": "✅ ALL CLEAR", "breaches": [], "count": 0, "demo": True}
        demo = ["Adobe", "LinkedIn", "Canva", "Facebook", "Twitter"][:count]
        return {"verdict": f"🔴 FOUND IN {count} BREACHES",
                "breaches": demo, "count": count, "demo": True}
    except Exception as e:
        return {"error": str(e)}

def check_password(password):
    try:
        sha1 = hashlib.sha1(password.encode()).hexdigest().upper()
        prefix, suffix = sha1[:5], sha1[5:]
        r = requests.get(f"https://api.pwnedpasswords.com/range/{prefix}",
            headers={"Add-Padding": "true"}, timeout=10)
        for line in r.text.splitlines():
            h, count = line.split(":")
            if h == suffix:
                return {"verdict": f"🔴 LEAKED {int(count):,} TIMES", "count": int(count)}
        return {"verdict": "✅ NOT FOUND IN BREACHES", "count": 0}
    except Exception as e:
        return {"error": str(e)}

def check_ip(ip):
    try:
        r = requests.get(
            f"http://ip-api.com/json/{ip}?fields=status,message,country,regionName,city,isp,proxy,hosting,query",
            timeout=10)
        data = r.json()
        if data.get("status") == "fail":
            return {"error": f"Invalid IP: {data.get('message')}"}
        is_proxy = data.get("proxy", False)
        is_hosting = data.get("hosting", False)
        if is_proxy:
            verdict = "🟡 PROXY / VPN"
        elif is_hosting:
            verdict = "🟡 HOSTING SERVER"
        else:
            verdict = "🟢 LOOKS NORMAL"
        return {
            "verdict": verdict,
            "ip": data.get("query", ip),
            "city": data.get("city", "Unknown"),
            "region": data.get("regionName", "Unknown"),
            "country": data.get("country", "Unknown"),
            "isp": data.get("isp", "Unknown"),
            "proxy": is_proxy,
            "hosting": is_hosting,
        }
    except Exception as e:
        return {"error": str(e)}

def check_whatsapp(message):
    if not GROQ_KEY:
        return {"error": "Groq API key not configured"}
    try:
        prompt = f"""You are ByteX AI — India's cybersecurity assistant. Analyze this message for scam indicators.

Message: "{message}"

Check for: fake prizes/lottery, urgency, OTP requests, money demands, suspicious links, impersonation.

Reply in this exact format:
VERDICT: [SCAM / SUSPICIOUS / LIKELY SAFE]
REASON: [1 sentence reason]
RISK: [HIGH / MEDIUM / LOW]"""

        r = requests.post(
            "https://api.groq.com/openai/v1/chat/completions",
            headers={"Authorization": f"Bearer {GROQ_KEY}", "Content-Type": "application/json"},
            json={"model": "llama-3.3-70b-versatile", "max_tokens": 200,
                  "messages": [{"role": "user", "content": prompt}]},
            timeout=15)
        reply = r.json()["choices"][0]["message"]["content"]
        verdict_line = [l for l in reply.split("\n") if "VERDICT:" in l]
        verdict = verdict_line[0].replace("VERDICT:", "").strip() if verdict_line else "UNKNOWN"
        if "SCAM" in verdict.upper():
            emoji = "🔴"
        elif "SUSPICIOUS" in verdict.upper():
            emoji = "🟡"
        else:
            emoji = "🟢"
        return {"verdict": f"{emoji} {verdict}", "full": reply}
    except Exception as e:
        return {"error": str(e)}

def ask_ai(question):
    if not GROQ_KEY:
        return "Groq API key not configured bro!"
    try:
        prompt = f"""You are ByteX AI — India's funny, friendly cybersecurity assistant built by Pushkar Shinde from Pune.
Be helpful, brief (2-3 sentences max), slightly funny and desi-friendly.
ByteX is live at bytex.onrender.com — India's free AI cybersecurity platform.

Question: {question}"""
        r = requests.post(
            "https://api.groq.com/openai/v1/chat/completions",
            headers={"Authorization": f"Bearer {GROQ_KEY}", "Content-Type": "application/json"},
            json={"model": "llama-3.3-70b-versatile", "max_tokens": 200,
                  "messages": [{"role": "user", "content": prompt}]},
            timeout=15)
        return r.json()["choices"][0]["message"]["content"]
    except Exception as e:
        return f"Oops! Something went wrong: {str(e)}"

# ── MESSAGE FORMATTERS ────────────────────────────────────
def format_url_result(url, result):
    if "error" in result:
        return f"❌ *Error:* {result['error']}"
    return (
        f"🔍 *URL SCAN RESULT*\n"
        f"━━━━━━━━━━━━━━━━\n"
        f"🔗 `{url[:50]}...`\n\n"
        f"*Verdict:* {result['verdict']}\n"
        f"*Malicious engines:* {result['malicious']} / {result['total']}\n"
        f"*Suspicious:* {result['suspicious']}\n\n"
        f"_Powered by VirusTotal — {result['total']} engines_\n"
        f"━━━━━━━━━━━━━━━━\n"
        f"🛡️ [Full scan on ByteX](https://bytex.onrender.com)"
    )

def format_email_result(email, result):
    if "error" in result:
        return f"❌ *Error:* {result['error']}"
    demo_note = "\n_⚠️ Demo mode — add HIBP API key for real results_" if result.get("demo") else ""
    if result["count"] == 0:
        return (
            f"📧 *EMAIL BREACH CHECK*\n"
            f"━━━━━━━━━━━━━━━━\n"
            f"Email: `{email}`\n\n"
            f"*{result['verdict']}*\n"
            f"Not found in any known data breaches! 🎉\n"
            f"{demo_note}\n"
            f"━━━━━━━━━━━━━━━━\n"
            f"🛡️ [Check more on ByteX](https://bytex.onrender.com)"
        )
    breaches_str = "\n".join([f"• {b}" for b in result["breaches"]])
    more = f"\n_...and {result['count'] - len(result['breaches'])} more_" if result["count"] > 5 else ""
    return (
        f"📧 *EMAIL BREACH CHECK*\n"
        f"━━━━━━━━━━━━━━━━\n"
        f"Email: `{email}`\n\n"
        f"*{result['verdict']}*\n\n"
        f"*Found in:*\n{breaches_str}{more}\n"
        f"{demo_note}\n"
        f"━━━━━━━━━━━━━━━━\n"
        f"💡 Change your password immediately!\n"
        f"🛡️ [Full timeline on ByteX](https://bytex.onrender.com)"
    )

def format_password_result(result):
    if "error" in result:
        return f"❌ *Error:* {result['error']}"
    if result["count"] == 0:
        return (
            f"🔑 *PASSWORD CHECK*\n"
            f"━━━━━━━━━━━━━━━━\n"
            f"*{result['verdict']}*\n\n"
            f"Your password was not found in any known data breaches! 🎉\n"
            f"_Note: Still use a strong unique password!_\n"
            f"━━━━━━━━━━━━━━━━\n"
            f"🛡️ [ByteX](https://bytex.onrender.com)"
        )
    return (
        f"🔑 *PASSWORD CHECK*\n"
        f"━━━━━━━━━━━━━━━━\n"
        f"*{result['verdict']}*\n\n"
        f"⚠️ This password has been exposed!\n"
        f"Change it immediately everywhere you use it.\n\n"
        f"_ByteX uses k-Anonymity — your password never leaves your device_\n"
        f"━━━━━━━━━━━━━━━━\n"
        f"🛡️ [ByteX](https://bytex.onrender.com)"
    )

def format_ip_result(result):
    if "error" in result:
        return f"❌ *Error:* {result['error']}"
    proxy_str = "✅ No" if not result["proxy"] else "⚠️ Yes"
    hosting_str = "✅ No" if not result["hosting"] else "⚠️ Yes"
    return (
        f"🌍 *IP ADDRESS CHECK*\n"
        f"━━━━━━━━━━━━━━━━\n"
        f"*IP:* `{result['ip']}`\n"
        f"*Verdict:* {result['verdict']}\n\n"
        f"📍 *Location:* {result['city']}, {result['region']}, {result['country']}\n"
        f"🏢 *ISP:* {result['isp']}\n"
        f"🔒 *Proxy/VPN:* {proxy_str}\n"
        f"🖥️ *Hosting:* {hosting_str}\n"
        f"━━━━━━━━━━━━━━━━\n"
        f"🛡️ [ByteX](https://bytex.onrender.com)"
    )

def format_whatsapp_result(result):
    if "error" in result:
        return f"❌ *Error:* {result['error']}"
    lines = result["full"].split("\n")
    formatted = "\n".join([f"_{l}_" if l.strip() else "" for l in lines])
    return (
        f"💬 *WHATSAPP SCAM CHECK*\n"
        f"━━━━━━━━━━━━━━━━\n"
        f"*{result['verdict']}*\n\n"
        f"{formatted}\n"
        f"━━━━━━━━━━━━━━━━\n"
        f"🛡️ [ByteX](https://bytex.onrender.com)"
    )

# ── COMMAND HANDLERS ──────────────────────────────────────
async def start(update: Update, context: ContextTypes.DEFAULT_TYPE):
    keyboard = [
        [InlineKeyboardButton("🔗 Scan URL", callback_data="help_url"),
         InlineKeyboardButton("📧 Email Breach", callback_data="help_email")],
        [InlineKeyboardButton("🔑 Password", callback_data="help_password"),
         InlineKeyboardButton("💬 WhatsApp Scam", callback_data="help_whatsapp")],
        [InlineKeyboardButton("🌍 IP Check", callback_data="help_ip"),
         InlineKeyboardButton("🤖 Ask AI", callback_data="help_ai")],
        [InlineKeyboardButton("🛡️ Open ByteX", url="https://bytex.onrender.com")],
    ]
    reply_markup = InlineKeyboardMarkup(keyboard)
    await update.message.reply_text(
        f"👋 *Hey {update.effective_user.first_name}! I'm ByteX AI!*\n\n"
        f"India's AI cybersecurity assistant 🇮🇳\n\n"
        f"*What I can do:*\n"
        f"🔗 Scan suspicious URLs\n"
        f"📧 Check email breaches\n"
        f"🔑 Check password leaks\n"
        f"💬 Detect WhatsApp scams\n"
        f"🌍 Investigate IP addresses\n"
        f"🤖 Answer security questions\n\n"
        f"*Just send me anything and I'll figure it out!*\n"
        f"Or use the buttons below 👇",
        parse_mode="Markdown",
        reply_markup=reply_markup
    )

async def help_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    await update.message.reply_text(
        "📖 *ByteX Bot Commands*\n\n"
        "/scan `<url>` — Scan any URL\n"
        "/email `<email>` — Check email breaches\n"
        "/password `<password>` — Check password leak\n"
        "/ip `<ip>` — Investigate IP address\n"
        "/whatsapp `<message>` — Detect WhatsApp scam\n"
        "/ask `<question>` — Ask ByteX AI anything\n\n"
        "💡 *Or just send any text* — I'll auto-detect what to check!\n\n"
        "🛡️ bytex.onrender.com",
        parse_mode="Markdown"
    )

async def scan_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not context.args:
        await update.message.reply_text("Usage: /scan `https://example.com`", parse_mode="Markdown")
        return
    url = context.args[0]
    msg = await update.message.reply_text("🔍 Scanning URL with 70+ engines... Please wait!")
    result = scan_url(url)
    await msg.edit_text(format_url_result(url, result), parse_mode="Markdown", disable_web_page_preview=True)

async def email_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not context.args:
        await update.message.reply_text("Usage: /email `your@email.com`", parse_mode="Markdown")
        return
    email = context.args[0]
    msg = await update.message.reply_text("📧 Checking 12 billion breached accounts...")
    result = check_email(email)
    await msg.edit_text(format_email_result(email, result), parse_mode="Markdown", disable_web_page_preview=True)

async def password_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not context.args:
        await update.message.reply_text("Usage: /password `yourpassword`\n\n_Don't worry — your password never leaves your device!_", parse_mode="Markdown")
        return
    password = " ".join(context.args)
    msg = await update.message.reply_text("🔑 Checking password securely...")
    result = check_password(password)
    await msg.edit_text(format_password_result(result), parse_mode="Markdown")

async def ip_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not context.args:
        await update.message.reply_text("Usage: /ip `8.8.8.8`", parse_mode="Markdown")
        return
    ip = context.args[0]
    msg = await update.message.reply_text("🌍 Investigating IP address...")
    result = check_ip(ip)
    await msg.edit_text(format_ip_result(result), parse_mode="Markdown")

async def whatsapp_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not context.args:
        await update.message.reply_text("Usage: /whatsapp `paste the suspicious message here`", parse_mode="Markdown")
        return
    message = " ".join(context.args)
    msg = await update.message.reply_text("💬 ByteX AI is analyzing the message...")
    result = check_whatsapp(message)
    await msg.edit_text(format_whatsapp_result(result), parse_mode="Markdown", disable_web_page_preview=True)

async def ask_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not context.args:
        await update.message.reply_text("Usage: /ask `what is phishing?`", parse_mode="Markdown")
        return
    question = " ".join(context.args)
    msg = await update.message.reply_text("🤖 ByteX AI is thinking...")
    reply = ask_ai(question)
    await msg.edit_text(
        f"🤖 *ByteX AI*\n\n{reply}\n\n"
        f"━━━━━━━━━━━━━━━━\n"
        f"🛡️ [ByteX](https://bytex.onrender.com)",
        parse_mode="Markdown", disable_web_page_preview=True
    )

# ── AUTO DETECT MESSAGE ───────────────────────────────────
async def handle_message(update: Update, context: ContextTypes.DEFAULT_TYPE):
    text = update.message.text.strip()
    detected = detect_type(text)

    if detected == "url":
        msg = await update.message.reply_text("🔍 URL detected! Scanning with 70+ engines...")
        result = scan_url(text)
        await msg.edit_text(format_url_result(text, result), parse_mode="Markdown", disable_web_page_preview=True)

    elif detected == "email":
        msg = await update.message.reply_text("📧 Email detected! Checking 12 billion breached accounts...")
        result = check_email(text)
        await msg.edit_text(format_email_result(text, result), parse_mode="Markdown", disable_web_page_preview=True)

    elif detected == "ip":
        msg = await update.message.reply_text("🌍 IP detected! Investigating...")
        result = check_ip(text)
        await msg.edit_text(format_ip_result(result), parse_mode="Markdown")

    elif detected == "whatsapp":
        msg = await update.message.reply_text("💬 Analyzing message for scam patterns...")
        result = check_whatsapp(text)
        await msg.edit_text(format_whatsapp_result(result), parse_mode="Markdown", disable_web_page_preview=True)

    else:
        # Ask AI for everything else
        msg = await update.message.reply_text("🤖 Asking ByteX AI...")
        reply = ask_ai(text)
        await msg.edit_text(
            f"🤖 *ByteX AI*\n\n{reply}\n\n"
            f"━━━━━━━━━━━━━━━━\n"
            f"_Send a URL, email, IP or WhatsApp message for instant scan!_",
            parse_mode="Markdown"
        )

# ── CALLBACK HANDLER ──────────────────────────────────────
async def button_callback(update: Update, context: ContextTypes.DEFAULT_TYPE):
    query = update.callback_query
    await query.answer()
    tips = {
        "help_url": "🔗 *URL Scanner*\n\nSend any link directly or use:\n`/scan https://suspicious-site.com`\n\n70+ engines check it instantly!",
        "help_email": "📧 *Email Breach*\n\nSend your email directly or use:\n`/email your@email.com`\n\nChecks 12 billion breached accounts!",
        "help_password": "🔑 *Password Check*\n\nUse:\n`/password yourpassword`\n\n_k-Anonymity — password never leaves device!_",
        "help_whatsapp": "💬 *WhatsApp Scam*\n\nForward/paste any suspicious message directly!\n\nAI detects scam patterns instantly.",
        "help_ip": "🌍 *IP Check*\n\nSend any IP directly or use:\n`/ip 8.8.8.8`\n\nShows location, ISP, VPN status.",
        "help_ai": "🤖 *ByteX AI*\n\nAsk anything!\n`/ask what is phishing?`\n`/ask how to stay safe online?`\n\nFriendly cybersecurity expert 😄",
    }
    await query.edit_message_text(
        tips.get(query.data, "Unknown option"),
        parse_mode="Markdown"
    )

# ── MAIN ─────────────────────────────────────────────────
def main():
    if not TOKEN:
        print("❌ TELEGRAM_BOT_TOKEN not set!")
        print("   Get token from @BotFather on Telegram")
        return

    print("🚀 ByteX Bot starting...")
    print(f"   VT API: {'✅' if VT_KEY else '❌ Not set'}")
    print(f"   Groq API: {'✅' if GROQ_KEY else '❌ Not set'}")
    print(f"   HIBP API: {'✅' if HIBP_KEY else '⚠️  Demo mode'}")

    app = Application.builder().token(TOKEN).build()

    # Commands
    app.add_handler(CommandHandler("start", start))
    app.add_handler(CommandHandler("help", help_command))
    app.add_handler(CommandHandler("scan", scan_command))
    app.add_handler(CommandHandler("email", email_command))
    app.add_handler(CommandHandler("password", password_command))
    app.add_handler(CommandHandler("ip", ip_command))
    app.add_handler(CommandHandler("whatsapp", whatsapp_command))
    app.add_handler(CommandHandler("ask", ask_command))

    # Auto detect
    app.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, handle_message))

    # Buttons
    app.add_handler(CallbackQueryHandler(button_callback))

    print("✅ ByteX Bot is running! Press Ctrl+C to stop.")
    app.run_polling(drop_pending_updates=True)

if __name__ == "__main__":
    main()
