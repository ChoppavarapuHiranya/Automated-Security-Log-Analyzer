from parser import parse_log_line
from detector import detect_brute_force
from user_detector import detect_repeated_failures
from sequence_detector import detect_success_after_failures
from ip_detector import detect_suspicious_ips
from time_detector import detect_unusual_login_time

from windows_parser import parse_windows_log
from windows_detector import detect_windows_brute_force

from report_generator import generate_report


# ==========================================================
# LINUX LOG ANALYSIS
# ==========================================================

linux_events = []


with open("../logs/auth.log", "r") as file:

    for line in file:

        result = parse_log_line(line)

        if result:
            linux_events.append(result)


# Linux detection modules

brute_force_alerts = detect_brute_force(linux_events)

user_alerts = detect_repeated_failures(linux_events)

sequence_alerts = detect_success_after_failures(linux_events)

ip_alerts = detect_suspicious_ips(linux_events)

time_alerts = detect_unusual_login_time(linux_events)


# ==========================================================
# WINDOWS LOG ANALYSIS
# ==========================================================

windows_events = parse_windows_log(
    "../logs/windows_security.csv"
)


windows_brute_force_alerts = detect_windows_brute_force(
    windows_events
)


# ==========================================================
# COMBINE ALL ALERTS
# ==========================================================

all_alerts = (
    brute_force_alerts
    + user_alerts
    + sequence_alerts
    + ip_alerts
    + time_alerts
    + windows_brute_force_alerts
)


# ==========================================================
# DISPLAY RESULTS
# ==========================================================

print("\n========================================")
print("       SECURITY LOG ANALYZER")
print("========================================")


print("\n===== LINUX SECURITY ALERTS =====\n")


for alert in brute_force_alerts:

    print("Alert Type:", alert["type"])
    print("Source IP:", alert["ip"])
    print("Failed Attempts:", alert["failed_attempts"])
    print("Severity:", alert["severity"])
    print()


for alert in user_alerts:

    print("Alert Type:", alert["type"])
    print("Username:", alert["username"])
    print("Failed Attempts:", alert["failed_attempts"])
    print("Severity:", alert["severity"])
    print()


for alert in sequence_alerts:

    print("Alert Type:", alert["type"])
    print("Username:", alert["username"])
    print("Source IP:", alert["ip"])
    print("Failed Attempts:", alert["failed_attempts"])
    print("Severity:", alert["severity"])
    print()


for alert in ip_alerts:

    print("Alert Type:", alert["type"])
    print("Source IP:", alert["ip"])
    print("Failed Attempts:", alert["failed_attempts"])
    print("Severity:", alert["severity"])
    print()


for alert in time_alerts:

    print("Alert Type:", alert["type"])
    print("Username:", alert["username"])
    print("Source IP:", alert["ip"])
    print("Timestamp:", alert["timestamp"])
    print("Severity:", alert["severity"])
    print()


print("\n===== WINDOWS SECURITY ALERTS =====\n")


for alert in windows_brute_force_alerts:

    print("Alert Type:", alert["type"])
    print("Source IP:", alert["ip"])
    print("Failed Attempts:", alert["failed_attempts"])
    print("Severity:", alert["severity"])
    print()


# ==========================================================
# GENERATE HTML REPORT
# ==========================================================

generate_report(
    linux_events,
    windows_events,
    all_alerts
)