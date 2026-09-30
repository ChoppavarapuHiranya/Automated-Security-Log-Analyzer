from collections import Counter


def detect_repeated_failures(events, threshold=3):

    failed_users = []

    for event in events:

        if event["event"] == "Failed password":
            failed_users.append(event["username"])

    counts = Counter(failed_users)

    alerts = []

    for username, count in counts.items():

        if count >= threshold:

            alerts.append({
                "type": "Repeated Authentication Failure",
                "username": username,
                "failed_attempts": count,
                "severity": "MEDIUM"
            })

    return alerts