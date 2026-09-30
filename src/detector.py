from collections import Counter


def detect_brute_force(events, threshold=5):

    failed_ips = []

    for event in events:

        if event["event"] == "Failed password":
            failed_ips.append(event["ip"])

    counts = Counter(failed_ips)

    alerts = []

    for ip, count in counts.items():

        if count >= threshold:

            alerts.append({
                "type": "Possible Brute Force Attack",
                "ip": ip,
                "failed_attempts": count,
                "severity": "HIGH"
            })

    return alerts