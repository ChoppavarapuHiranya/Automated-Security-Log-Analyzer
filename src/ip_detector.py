from collections import Counter


def detect_suspicious_ips(events, threshold=3):

    failed_ips = []

    for event in events:

        if event["event"] == "Failed password":
            failed_ips.append(event["ip"])

    counts = Counter(failed_ips)

    alerts = []

    for ip, count in counts.items():

        if count >= threshold:

            alerts.append({
                "type": "Suspicious Source IP",
                "ip": ip,
                "failed_attempts": count,
                "severity": "MEDIUM"
            })

    return alerts
