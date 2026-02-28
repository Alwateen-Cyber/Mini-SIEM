import re
from collections import Counter

LOG_FILE = "sample.log"
ALERT_FILE = "alerts.txt"
THRESHOLD = 5

def extract_failed_ips(log_content):
    pattern = r"Failed login from (\d+\.\d+\.\d+\.\d+)"
    return re.findall(pattern, log_content)

def analyze_logs():
    with open(LOG_FILE, "r") as file:
        logs = file.read()

    failed_ips = extract_failed_ips(logs)
    ip_count = Counter(failed_ips)

    alerts = []

    for ip, count in ip_count.items():
        if count > THRESHOLD:
            alerts.append(f"[HIGH] Suspicious activity detected from {ip} - {count} failed attempts")

    return alerts

def write_alerts(alerts):
    with open(ALERT_FILE, "w") as file:
        for alert in alerts:
            file.write(alert + "\n")

def main():
    alerts = analyze_logs()

    if alerts:
        write_alerts(alerts)
        print("Alerts generated successfully.")
    else:
        print("No suspicious activity detected.")

if __name__ == "__main__":
    main()
