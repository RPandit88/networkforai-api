from flask import Flask, request, jsonify
from flask_cors import CORS
import re
import os
import requests

app = Flask(__name__)
CORS(app)

# ─── GEMINI CONFIG ────────────────────────────────────────────────
GEMINI_KEY   = os.environ.get("GEMINI_KEY", "")
GEMINI_URL   = "https://generativelanguage.googleapis.com/v1beta/models/gemini-2.0-flash:generateContent"


# ─── LOG REDACTION ────────────────────────────────────────────────

def redact_log(text, rules):
    out    = text
    counts = {"ip": 0, "mac": 0, "as": 0, "host": 0, "cred": 0}
    ip_map = {}
    as_map = {}
    ip_idx = [1]
    as_idx = [1]

    if rules.get("cred"):
        def replace_cred(m):
            counts["cred"] += 1
            return m.group(1) + ": [REDACTED]"
        out = re.sub(
            r'(password|passwd|secret|community|auth[\s\-]?key|md5|enable)'
            r'\s*[:=]?\s*\S+',
            replace_cred, out, flags=re.IGNORECASE
        )

    if rules.get("mac"):
        def replace_mac(m):
            counts["mac"] += 1
            return "[MAC_REDACTED]"
        out = re.sub(
            r'([0-9a-fA-F]{2}[:\-]){5}[0-9a-fA-F]{2}',
            replace_mac, out
        )

    if rules.get("as"):
        def replace_as(m):
            counts["as"] += 1
            n = m.group(1)
            if n not in as_map:
                as_map[n] = "AS{}".format(as_idx[0])
                as_idx[0] += 1
            return as_map[n]
        out = re.sub(
            r'\bAS\s?(\d{1,10})\b',
            replace_as, out, flags=re.IGNORECASE
        )

    if rules.get("ip"):
        def replace_ip(m):
            counts["ip"] += 1
            full   = m.group(0)
            key    = re.sub(r'\/\d+$', '', full)
            suffix = full[len(key):]
            if key not in ip_map:
                ip_map[key] = "[IP_{}]".format(str(ip_idx[0]).zfill(3))
                ip_idx[0] += 1
            return ip_map[key] + suffix
        out = re.sub(
            r'\b(\d{1,3}\.){3}\d{1,3}(\/\d{1,2})?\b',
            replace_ip, out
        )

    if rules.get("host"):
        def replace_host(m):
            counts["host"] += 1
            return "[HOST_REDACTED]"
        out = re.sub(
            r'\b(router|switch|sw|pe|ce|rr|spine|leaf|fw|'
            r'firewall|core|edge|agg|dist)-[\w\-]+\b',
            replace_host, out, flags=re.IGNORECASE
        )

    return {"redacted": out, "counts": counts}


@app.route("/redact", methods=["POST"])
def redact():
    body = request.get_json()
    if not body:
        return jsonify({"error": "No JSON body"}), 400
    log_text = body.get("log", "")
    rules    = body.get("rules", {
        "ip": True, "mac": True,
        "as": True, "host": True, "cred": True
    })
    return jsonify(redact_log(log_text, rules))


# ─── ANOMALY DETECTION ────────────────────────────────────────────

@app.route("/analyze", methods=["POST"])
def analyze():
    if not GEMINI_KEY:
        return jsonify({"error": "GEMINI_KEY not configured on server"}), 500

    body = request.get_json()
    if not body:
        return jsonify({"error": "No JSON body"}), 400

    log_text = body.get("log", "").strip()
    env      = body.get("env",   "Production")
    ntype    = body.get("ntype", "ISP / Transit")
    focus    = body.get("focus", "All anomalies")
    ctx      = body.get("ctx",   "")

    if not log_text:
        return jsonify({"error": "No log text provided"}), 400

    prompt = """You are a senior network operations engineer. Analyze this network log for anomalies and security threats.

Environment: {env} | Network: {ntype} | Focus: {focus}{ctx}

Log:
{log}

Reply ONLY with valid JSON, no markdown fences, no extra text:
{{"anomalies":[{{"severity":"critical|warning|info|normal","type":"short label","title":"concise title","description":"2-3 sentences explaining what was detected and why it matters","recommendation":"specific actionable step"}}],"summary":"3-4 sentence executive summary of overall health and key findings","counts":{{"critical":0,"warning":0,"info":0,"normal":0}}}}""".format(
        env=env,
        ntype=ntype,
        focus=focus,
        ctx=" | Context: " + ctx if ctx else "",
        log=log_text
    )

    try:
        resp = requests.post(
            GEMINI_URL + "?key=" + GEMINI_KEY,
            json={
                "contents": [{"parts": [{"text": prompt}]}],
                "generationConfig": {"temperature": 0.2, "maxOutputTokens": 1500}
            },
            timeout=30
        )

        if resp.status_code != 200:
            error_data = resp.json()
            error_msg  = error_data.get("error", {}).get("message", "Unknown Gemini error")
            return jsonify({"error": error_msg}), resp.status_code

        data = resp.json()
        raw  = data["candidates"][0]["content"]["parts"][0]["text"]
        clean = raw.replace("```json", "").replace("```", "").strip()

        import json
        parsed = json.loads(clean)
        return jsonify(parsed)

    except requests.exceptions.Timeout:
        return jsonify({"error": "Gemini API timed out. Try again."}), 504
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# ─── HEALTH CHECK ─────────────────────────────────────────────────

@app.route("/health", methods=["GET"])
def health():
    return jsonify({
        "status":      "ok",
        "gemini_key":  "configured" if GEMINI_KEY else "MISSING"
    })


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(debug=False, host="0.0.0.0", port=port)
