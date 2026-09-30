from datetime import datetime


def detect_unusual_login_time(events, start_hour=8, end_hour=18):

    alerts = []

    for event in events:

        time_part = event["timestamp"].split()[2]

        login_time = datetime.strptime(time_part, "%H:%M:%S")

        hour = login_time.hour

        if hour < start_hour or hour >= end_hour:

            alerts.append({
                "type": "Unusual Login Time",
                "username": event["username"],
                "ip": event["ip"],
                "timestamp": event["timestamp"],
                "severity": "MEDIUM"
            })

    return alerts