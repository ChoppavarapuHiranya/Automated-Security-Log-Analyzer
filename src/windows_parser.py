import csv


def parse_windows_log(file_path):

    events = []

    with open(file_path, "r", newline="") as file:

        reader = csv.DictReader(file)

        for row in reader:

            event = {
                "timestamp": row["timestamp"],
                "event_id": row["event_id"],
                "username": row["username"],
                "ip": row["ip"],
                "status": row["status"]
            }

            events.append(event)

    return events