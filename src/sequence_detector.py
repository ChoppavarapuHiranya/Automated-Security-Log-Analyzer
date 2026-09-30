def detect_success_after_failures(events, threshold=3):

    alerts = []

    for i, event in enumerate(events):

        if event["event"] == "Accepted password":

            username = event["username"]
            ip = event["ip"]

            previous_events = events[:i]

            failed_count = 0

            for previous in previous_events:

                if (
                    previous["event"] == "Failed password"
                    and previous["username"] == username
                    and previous["ip"] == ip
                ):
                    failed_count += 1

            if failed_count >= threshold:

                alerts.append({
                    "type": "Successful Login After Repeated Failures",
                    "username": username,
                    "ip": ip,
                    "failed_attempts": failed_count,
                    "severity": "HIGH"
                })

    return alerts