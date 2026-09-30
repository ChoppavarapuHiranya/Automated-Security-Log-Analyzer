from datetime import datetime


def generate_report(
    linux_events,
    windows_events,
    alerts,
    output_file="../reports/security_report.html"
):

    total_linux = len(linux_events)
    total_windows = len(windows_events)

    failed_linux = sum(
        1 for event in linux_events
        if event["event"] == "Failed password"
    )

    successful_linux = sum(
        1 for event in linux_events
        if event["event"] == "Accepted password"
    )

    failed_windows = sum(
        1 for event in windows_events
        if event["status"] == "Failed"
    )

    successful_windows = sum(
        1 for event in windows_events
        if event["status"] == "Success"
    )

    high_alerts = sum(
        1 for alert in alerts
        if alert["severity"] == "HIGH"
    )

    medium_alerts = sum(
        1 for alert in alerts
        if alert["severity"] == "MEDIUM"
    )

    generated_time = datetime.now().strftime(
        "%Y-%m-%d %H:%M:%S"
    )

    alert_rows = ""

    for alert in alerts:

        alert_rows += f"""
        <tr>
            <td>{alert.get("type", "")}</td>
            <td>{alert.get("username", "-")}</td>
            <td>{alert.get("ip", "-")}</td>
            <td>{alert.get("failed_attempts", "-")}</td>
            <td>{alert.get("timestamp", "-")}</td>
            <td>{alert.get("severity", "")}</td>
        </tr>
        """

    html = f"""
<!DOCTYPE html>
<html>

<head>

    <title>Security Log Analysis Report</title>

    <style>

        body {{
            font-family: Arial, sans-serif;
            margin: 40px;
        }}

        h1 {{
            text-align: center;
        }}

        .summary {{
            display: flex;
            gap: 20px;
            margin: 30px 0;
        }}

        .card {{
            border: 1px solid #ccc;
            padding: 20px;
            flex: 1;
            text-align: center;
        }}

        table {{
            width: 100%;
            border-collapse: collapse;
            margin-top: 25px;
        }}

        th, td {{
            border: 1px solid #ccc;
            padding: 10px;
            text-align: left;
        }}

        th {{
            background-color: #f2f2f2;
        }}

    </style>

</head>

<body>

<h1>Security Log Analysis Report</h1>

<p>
Generated: {generated_time}
</p>


<h2>Event Summary</h2>

<div class="summary">

    <div class="card">
        <h3>Linux Events</h3>
        <p>{total_linux}</p>
    </div>

    <div class="card">
        <h3>Windows Events</h3>
        <p>{total_windows}</p>
    </div>

    <div class="card">
        <h3>High Alerts</h3>
        <p>{high_alerts}</p>
    </div>

    <div class="card">
        <h3>Medium Alerts</h3>
        <p>{medium_alerts}</p>
    </div>

</div>


<h2>Authentication Summary</h2>

<ul>

    <li>Linux Failed Logins: {failed_linux}</li>

    <li>Linux Successful Logins: {successful_linux}</li>

    <li>Windows Failed Logins: {failed_windows}</li>

    <li>Windows Successful Logins: {successful_windows}</li>

</ul>


<h2>Detected Security Alerts</h2>

<table>

    <tr>
        <th>Alert Type</th>
        <th>Username</th>
        <th>Source IP</th>
        <th>Failed Attempts</th>
        <th>Timestamp</th>
        <th>Severity</th>
    </tr>

    {alert_rows}

</table>


<h2>Analysis</h2>

<p>
The security log analyzer identified repeated authentication
failures, suspicious source IP activity, unusual login timing,
and potential brute-force attacks from the supplied security logs.
</p>

<p>
The system analyzes both Linux authentication logs and
Windows Security Event-style records and presents the detected
security events in a consolidated analytical report.
</p>

</body>

</html>
"""

    with open(output_file, "w", encoding="utf-8") as file:

        file.write(html)

    print("\nReport generated successfully:")
    print(output_file)