from flask import Flask, request, jsonify
from flask_cors import CORS
import re
import os

app = Flask(__name__)
CORS(app)


def redact_log(text, rules):
    out = text
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
            full = m.group(0)
            key = re.sub(r'\/\d+$', '', full)
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
        return jsonify({"error": "No JSON body received"}), 400
    log_text = body.get("log", "")
    rules = body.get("rules", {
        "ip": True, "mac": True,
        "as": True, "host": True, "cred": True
    })
    result = redact_log(log_text, rules)
    return jsonify(result)


@app.route("/health", methods=["GET"])
def health():
    return jsonify({"status": "ok"})


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(debug=False, host="0.0.0.0", port=port)
