from flask import Flask, request, jsonify
from flask_cors import CORS
import re
import os
import time
import json
import requests

app = Flask(__name__)
CORS(app, resources={r"/*": {"origins": "*", "methods": ["GET", "POST", "OPTIONS"], "allow_headers": ["Content-Type", "Authorization"]}})

@app.after_request
def add_cors_headers(response):
    response.headers["Access-Control-Allow-Origin"]  = "*"
    response.headers["Access-Control-Allow-Methods"] = "GET, POST, OPTIONS"
    response.headers["Access-Control-Allow-Headers"] = "Content-Type, Authorization"
    return response

@app.route("/analyze", methods=["OPTIONS"])
@app.route("/redact",  methods=["OPTIONS"])
@app.route("/plan",    methods=["OPTIONS"])
@app.route("/health",  methods=["OPTIONS"])
def handle_options():
    from flask import Response
    r = Response()
    r.headers["Access-Control-Allow-Origin"]  = "*"
    r.headers["Access-Control-Allow-Methods"] = "GET, POST, OPTIONS"
    r.headers["Access-Control-Allow-Headers"] = "Content-Type, Authorization"
    return r, 200

GEMINI_KEY = os.environ.get("GEMINI_KEY", "")
GEMINI_URL = "https://generativelanguage.googleapis.com/v1beta/models/gemini-2.5-flash:generateContent"



def extract_json(raw):
    clean = re.sub(r"```json\s*", "", raw)
    clean = re.sub(r"```\s*", "", clean).strip()
    match = re.search(r"\{.*\}", clean, re.DOTALL)
    if match:
        clean = match.group(0)
    return json.loads(clean)


def call_gemini(prompt, max_tokens=8192):
    """Call Gemini with retry logic. Returns parsed JSON or raises."""
    if not GEMINI_KEY:
        raise ValueError("GEMINI_KEY not configured on server")

    last_error = ""
    for attempt in range(3):
        try:
            resp = requests.post(
                GEMINI_URL + "?key=" + GEMINI_KEY,
                json={
                    "contents": [{"parts": [{"text": prompt}]}],
                    "generationConfig": {"temperature": 0.2, "maxOutputTokens": max_tokens}
                },
                timeout=45
            )
            if resp.status_code in (429, 503):
                last_error = resp.json().get("error", {}).get("message", "Overloaded")
                time.sleep(5)
                continue
            if resp.status_code != 200:
                error_msg = resp.json().get("error", {}).get("message", "Unknown error")
                raise ValueError(error_msg)

            data = resp.json()
            raw  = data["candidates"][0]["content"]["parts"][0]["text"]
            return extract_json(raw)

        except requests.exceptions.Timeout:
            last_error = "Timeout"
            time.sleep(3)
            continue
        except (ValueError, KeyError) as e:
            raise
        except Exception as e:
            raise ValueError(str(e))

    raise ValueError("Gemini unavailable after 3 attempts: " + last_error)


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
            r"(password|passwd|secret|community|auth[\s\-]?key|md5|enable)\s*[:=]?\s*\S+",
            replace_cred, out, flags=re.IGNORECASE
        )

    if rules.get("mac"):
        def replace_mac(m):
            counts["mac"] += 1
            return "[MAC_REDACTED]"
        out = re.sub(r"([0-9a-fA-F]{2}[:\-]){5}[0-9a-fA-F]{2}", replace_mac, out)

    if rules.get("as"):
        def replace_as(m):
            counts["as"] += 1
            n = m.group(1)
            if n not in as_map:
                as_map[n] = "AS{}".format(as_idx[0])
                as_idx[0] += 1
            return as_map[n]
        out = re.sub(r"\bAS\s?(\d{1,10})\b", replace_as, out, flags=re.IGNORECASE)

    if rules.get("ip"):
        def replace_ip(m):
            counts["ip"] += 1
            full   = m.group(0)
            key    = re.sub(r"\/\d+$", "", full)
            suffix = full[len(key):]
            if key not in ip_map:
                ip_map[key] = "[IP_{}]".format(str(ip_idx[0]).zfill(3))
                ip_idx[0] += 1
            return ip_map[key] + suffix
        out = re.sub(r"\b(\d{1,3}\.){3}\d{1,3}(\/\d{1,2})?\b", replace_ip, out)

    if rules.get("host"):
        def replace_host(m):
            counts["host"] += 1
            return "[HOST_REDACTED]"
        out = re.sub(
            r"\b(router|switch|sw|pe|ce|rr|spine|leaf|fw|firewall|core|edge|agg|dist)-[\w\-]+\b",
            replace_host, out, flags=re.IGNORECASE
        )

    return {"redacted": out, "counts": counts}


@app.route("/redact", methods=["POST"])
def redact():
    body = request.get_json()
    if not body:
        return jsonify({"error": "No JSON body"}), 400
    log_text = body.get("log", "")
    rules    = body.get("rules", {"ip": True, "mac": True, "as": True, "host": True, "cred": True})
    return jsonify(redact_log(log_text, rules))



@app.route("/analyze", methods=["POST"])
def analyze():
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

    prompt = (
        "You are a senior network operations engineer. Analyze this network log for anomalies.\n\n"
        "Environment: {env} | Network: {ntype} | Focus: {focus}{ctx}\n\n"
        "Log:\n{log}\n\n"
        "Reply ONLY with valid JSON, no markdown, no code fences:\n"
        '{{"anomalies":[{{"severity":"critical|warning|info|normal","type":"short label",'
        '"title":"concise title","description":"2-3 sentences","recommendation":"actionable step"}}],'
        '"summary":"3-4 sentence summary","counts":{{"critical":0,"warning":0,"info":0,"normal":0}}}}'
    ).format(
        env=env, ntype=ntype, focus=focus,
        ctx=" | Context: " + ctx if ctx else "",
        log=log_text
    )

    try:
        result = call_gemini(prompt)
        return jsonify(result)
    except Exception as e:
        return jsonify({"error": str(e)}), 500



EOL_MODELS = [
    "WS-C2960", "WS-C3560", "WS-C3750", "WS-C4500",
    "N5K-C5010", "N5K-C5020", "WS-C6500", "WS-C4948"
]

EOS_VERSIONS = [
    "12.2", "15.0", "15.1", "15.2",
    "7.0(3)I4", "7.0(3)I6", "9.2", "7.3"
]


def score_device(device):
    """Score a device 0-100 on replacement urgency based on submitted data."""
    score   = 0
    reasons = []

    if not device.get("reachable", True):
        return {"score": 100, "priority": "CRITICAL",
                "reasons": ["Device unreachable — may already be failed"]}

    model   = device.get("model", "")
    version = device.get("version", "")
    uptime  = device.get("uptime_days", 0)

    if any(m in model for m in EOL_MODELS):
        score += 40
        reasons.append("EOL hardware model: {}".format(model))

    if any(v in version for v in EOS_VERSIONS):
        score += 25
        reasons.append("End of support software: {}".format(version))

    if uptime > 1825:
        score += 20
        reasons.append("Uptime {} days — over 5 years without reload".format(uptime))
    elif uptime > 1095:
        score += 10
        reasons.append("Uptime {} days — over 3 years without reload".format(uptime))

    hw_alerts = device.get("hw_alerts", 0)
    if hw_alerts > 0:
        score += min(hw_alerts * 10, 30)
        reasons.append("{} hardware alerts (fan/power/temp)".format(hw_alerts))

    error_ports = device.get("error_ports", 0)
    if error_ports > 0:
        score += min(error_ports * 5, 20)
        reasons.append("{} interfaces with high error/CRC counts".format(error_ports))

    high_util = device.get("high_util_ports", 0)
    if high_util > 0:
        score += min(high_util * 3, 15)
        reasons.append("{} interfaces above 85% utilization".format(high_util))

    total  = device.get("total_ports", 0)
    active = device.get("active_ports", 0)
    if total > 0 and (active / total) > 0.90:
        score += 15
        reasons.append("Port capacity at {}% — needs larger switch".format(
            round(active / total * 100)))

    score = min(score, 100)
    if score >= 75:   priority = "CRITICAL"
    elif score >= 50: priority = "HIGH"
    elif score >= 25: priority = "MEDIUM"
    else:             priority = "LOW"

    return {"score": score, "priority": priority, "reasons": reasons}


def build_ai_prompt(devices_scored):
    """Build a prompt for Gemini to analyze the scored device list."""
    summary_lines = []
    for d in devices_scored:
        summary_lines.append(
            "Device: {name} | Model: {model} | SW: {version} | "
            "Uptime: {uptime_days} days | Score: {score} | Priority: {priority} | "
            "Reasons: {reasons}".format(
                name=d.get("name", "unknown"),
                model=d.get("model", "unknown"),
                version=d.get("version", "unknown"),
                uptime_days=d.get("uptime_days", 0),
                score=d.get("score", 0),
                priority=d.get("priority", "LOW"),
                reasons=", ".join(d.get("reasons", []))
            )
        )

    device_summary = "\n".join(summary_lines)

    return (
        "You are a senior network engineer specializing in infrastructure lifecycle management. "
        "Analyze this network switch inventory and provide replacement planning recommendations.\n\n"
        "DEVICE INVENTORY:\n{devices}\n\n"
        "Provide a comprehensive replacement plan. Reply ONLY with valid JSON, no markdown:\n"
        '{{"executive_summary":"3-4 sentence overall assessment of network health and urgency",'
        '"total_devices":{total},'
        '"replacement_phases":[{{'
        '"phase":1,"timeline":"0-3 months","priority":"CRITICAL",'
        '"devices":["device names"],'
        '"rationale":"why these must be replaced first",'
        '"estimated_risk":"risk of not replacing"}}],'
        '"budget_guidance":{{'
        '"immediate":"devices needing replacement in 0-3 months",'
        '"short_term":"devices needing replacement in 3-12 months",'
        '"long_term":"devices that can wait 1-2 years"}},'
        '"recommendations":["actionable recommendation 1","actionable recommendation 2"],'
        '"risk_assessment":"paragraph about overall risk if replacements are delayed"}}}}'
    ).format(devices=device_summary, total=len(devices_scored))


@app.route("/plan", methods=["POST"])
def plan():
    body = request.get_json()
    if not body:
        return jsonify({"error": "No JSON body"}), 400

    devices = body.get("devices", [])
    if not devices:
        return jsonify({"error": "No devices provided"}), 400

  
    scored = []
    for device in devices:
        device_score = score_device(device)
        scored.append({**device, **device_score})

    # sort by score descending
    scored.sort(key=lambda x: x["score"], reverse=True)

    # get AI analysis
    ai_result = {}
    try:
        prompt    = build_ai_prompt(scored)
        ai_result = call_gemini(prompt)
    except Exception as e:
        ai_result = {"error": "AI analysis unavailable: {}".format(str(e))}

    return jsonify({
        "devices":  scored,
        "ai_plan":  ai_result,
        "counts": {
            "critical": len([d for d in scored if d["priority"] == "CRITICAL"]),
            "high":     len([d for d in scored if d["priority"] == "HIGH"]),
            "medium":   len([d for d in scored if d["priority"] == "MEDIUM"]),
            "low":      len([d for d in scored if d["priority"] == "LOW"])
        }
    })



@app.route("/health", methods=["GET"])
def health():
    return jsonify({
        "status":     "ok",
        "gemini_key": "configured" if GEMINI_KEY else "MISSING"
    })


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(debug=False, host="0.0.0.0", port=port)
