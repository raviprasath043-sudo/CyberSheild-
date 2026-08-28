from collections import Counter
from datetime import datetime, timedelta


# =========================================
# Threat Score Calculation
# =========================================

def calculate_score(alert_type, count):
    """
    Calculate a threat score from 0 to 100.
    """

    if alert_type == "Possible Brute Force":
        score = 60 + (count * 8)

    elif alert_type == "Port Scan":
        score = 70 + (count * 5)

    elif alert_type == "Suspicious Connection Activity":
        score = 45 + (count * 5)

    else:
        score = 20

    return min(score, 100)


# =========================================
# Severity Calculation
# =========================================

def get_severity(score):
    """
    Convert threat score into severity.
    """

    if score >= 80:
        return "CRITICAL"

    elif score >= 60:
        return "HIGH"

    elif score >= 40:
        return "MEDIUM"

    else:
        return "LOW"


# =========================================
# Parse Event Time
# =========================================

def parse_event_time(event_time):
    """
    Convert an event timestamp into a datetime object.
    """

    try:
        return datetime.fromisoformat(
            event_time.replace("Z", "+00:00")
        )

    except (ValueError, AttributeError):
        return None


# =========================================
# Main Detection Engine
# =========================================

def analyze_events(events):

    alerts = []

    # -----------------------------------------
    # Rule 1: Time-Aware Possible Brute Force
    # -----------------------------------------

    failed_logins = [
        event for event in events
        if "failed" in event["event_type"].lower()
        and "login" in event["event_type"].lower()
    ]

    ip_groups = {}

    for event in failed_logins:

        ip = event["source_ip"]

        if ip not in ip_groups:
            ip_groups[ip] = []

        ip_groups[ip].append(event)

    for ip, ip_events in ip_groups.items():

        valid_events = []

        for event in ip_events:

            event_time = parse_event_time(
                event["event_time"]
            )

            if event_time is not None:
                valid_events.append(
                    (event_time, event)
                )

        valid_events.sort(
            key=lambda item: item[0]
        )

        for index in range(len(valid_events)):

            start_time = valid_events[index][0]

            window_events = [
                event
                for event_time, event in valid_events[index:]
                if event_time <= start_time + timedelta(minutes=5)
            ]

            count = len(window_events)

            if count >= 3:

                score = calculate_score(
                    "Possible Brute Force",
                    count
                )

                alerts.append({
                    "source_ip": ip,
                    "type": "Possible Brute Force",
                    "message": (
                        f"{count} failed login attempts "
                        f"within 5 minutes"
                    ),
                    "count": count,
                    "score": score,
                    "severity": get_severity(score)
                })

                break

    # -----------------------------------------
    # Rule 2: Port Scan
    # -----------------------------------------

    port_scan_ips = set()

    for event in events:

        if "port scan" in event["event_type"].lower():
            port_scan_ips.add(event["source_ip"])

    for ip in port_scan_ips:

        count = sum(
            1
            for event in events
            if event["source_ip"] == ip
            and "port scan" in event["event_type"].lower()
        )

        score = calculate_score(
            "Port Scan",
            count
        )

        alerts.append({
            "source_ip": ip,
            "type": "Port Scan",
            "message": "Possible network reconnaissance detected",
            "count": count,
            "score": score,
            "severity": get_severity(score)
        })

    # -----------------------------------------
    # Rule 3: Suspicious Connections
    # -----------------------------------------

    connection_ips = set()

    for event in events:

        if "multiple connection" in event["event_type"].lower():
            connection_ips.add(event["source_ip"])

    for ip in connection_ips:

        count = sum(
            1
            for event in events
            if event["source_ip"] == ip
            and "multiple connection" in event["event_type"].lower()
        )

        score = calculate_score(
            "Suspicious Connection Activity",
            count
        )

        alerts.append({
            "source_ip": ip,
            "type": "Suspicious Connection Activity",
            "message": "Multiple connection attempts detected",
            "count": count,
            "score": score,
            "severity": get_severity(score)
        })

    # -----------------------------------------
    # Sort Highest Threat First
    # -----------------------------------------

    alerts.sort(
        key=lambda alert: alert["score"],
        reverse=True
    )

    return alerts