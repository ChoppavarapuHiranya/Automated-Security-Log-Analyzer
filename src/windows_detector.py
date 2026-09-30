from collections import Counter


def detect_windows_brute_force(events, threshold=5):

    failed_ips = []

    for event in events:

        if event["event_id"] == "4625":
            failed_ips.append(event["ip"])

    counts = Counter(failed_ips)

    alerts = []

    for ip, count in counts.items():

        if count >= threshold:

            alerts.append({
                "type": "Windows Brute Force Attack",
                "ip": ip,
                "failed_attempts": count,
                "severity": "HIGH"
            })

    return alerts