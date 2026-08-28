import subprocess
import xml.etree.ElementTree as ET
import requests
import re
import time


API_URL = "http://127.0.0.1:5000/api/events"

CHECK_INTERVAL = 5
STATE_FILE="collector_state.txt"

# =========================================
# Get Existing Events From CyberShield
# =========================================

def get_existing_events():

    try:

        response = requests.get(
            API_URL,
            timeout=5
        )

        response.raise_for_status()

        return response.json()

    except requests.RequestException as error:

        print("Could not retrieve existing events:")
        print(error)

        return []

# =========================================
# Collector State
# =========================================

def load_last_record_id():

    try:

        with open(STATE_FILE, "r") as file:

            return int(file.read().strip())

    except (FileNotFoundError, ValueError):

        return None


def save_last_record_id(record_id):

    with open(STATE_FILE, "w") as file:

        file.write(str(record_id))

# =========================================
# Get Failed Windows Logins
# =========================================

def get_failed_logins():

    command = [
        "wevtutil",
        "qe",
        "Security",
        "/q:*[System[(EventID=4625)]]",
        "/f:xml",
        "/c:50",
        "/rd:true"
    ]

    result = subprocess.run(
        command,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="ignore"
    )

    if result.returncode != 0:

        print("Could not read Windows Security Event Log.")
        print(result.stderr)

        return []

    xml_data = result.stdout

    events = []

    xml_blocks = re.findall(
        r"<Event.*?</Event>",
        xml_data,
        re.DOTALL
    )

    for block in xml_blocks:

        try:

            root = ET.fromstring(block)

            namespace = {
                "e":
                "http://schemas.microsoft.com/win/2004/08/events/event"
            }

            system = root.find(
                "e:System",
                namespace
            )
            record_id_node = system.find(
              "e:EventRecordID",
                namespace
            )

            record_id = int(
                record_id_node.text
            ) if record_id_node is not None else 0

            time_node = system.find(
                "e:TimeCreated",
                namespace
            )

            event_time = time_node.attrib.get(
                "SystemTime",
                ""
            )

            source_ip = "Unknown"

            for data in root.findall(
                ".//e:EventData/e:Data",
                namespace
            ):

                if data.attrib.get("Name") == "IpAddress":

                    source_ip = data.text or "Unknown"

                    break

            events.append({
                "record_id":record_id,
                "event_time": event_time,
                "source_ip": source_ip,
                "event_type": "Failed Windows Login",
                "severity": "HIGH"
            })

        except ET.ParseError:

            continue

    return events


# =========================================
# Check Whether Event Already Exists
# =========================================

def event_exists(event, existing_events):

    for existing in existing_events:

        if (
            existing.get("event_time") == event["event_time"]
            and existing.get("source_ip") == event["source_ip"]
            and existing.get("event_type") == event["event_type"]
        ):

            return True

    return False


# =========================================
# Send Event To CyberShield
# =========================================

def send_event(event):

    try:

        api_event = {
            "event_time": event["event_time"],
            "source_ip": event["source_ip"],
            "event_type": event["event_type"],
            "severity": event["severity"]
        }

        response = requests.post(
            API_URL,
            json=api_event,
            timeout=5
        )
        

        print(
            response.status_code,
            response.json()
        )

        return response.status_code == 201

    except requests.RequestException as error:

        print("Could not connect to CyberShield:")
        print(error)

        return False


# =========================================
# Continuous Monitoring
# =========================================

def monitor():

    print("====================================")
    print(" CyberShield Real-Time Log Collector")
    print("====================================")
    print(f"Checking every {CHECK_INTERVAL} seconds...")
    print("Press CTRL+C to stop.")
    print()

    last_record_id=load_last_record_id()
    while True:

        existing_events = get_existing_events()

        events = get_failed_logins()
        # First run: establish a baseline
        if last_record_id is None:

            if events:

                latest_record_id = max(
                  event["record_id"]
                  for event in events
                )

                save_last_record_id(
                    latest_record_id
                )

                last_record_id = latest_record_id

                print(
                  f"Initial baseline established at "
                  f"EventRecordID {last_record_id}"
                )

            else:

               print("No failed login events found.")

            time.sleep(CHECK_INTERVAL)

            continue

        print(
            f"\nFound {len(events)} failed login events."
        )

        new_events = 0
        duplicate_events = 0
        new_windows_events = [
           event
           for event in events
           if event["record_id"] > last_record_id
        ]

        for event in new_windows_events:

            if event_exists(
                event,
                existing_events
            ):

                duplicate_events += 1

                print(
                    "Skipping duplicate event:"
                )

                print(event)

                continue

            print("\nSending new event:")
            print(event)

            success = send_event(event)

            if success:

                new_events += 1

                # Add it locally so it is not
                # sent again during this cycle.
                existing_events.append(event)

        print("\n------------------------------------")
        print(f"New events sent: {new_events}")
        print(f"Duplicates skipped: {duplicate_events}")
        print("------------------------------------")

        print(
            f"Waiting {CHECK_INTERVAL} seconds..."
        )

        time.sleep(CHECK_INTERVAL)


# =========================================
# Main
# =========================================

if __name__ == "__main__":

    try:

        monitor()

    except KeyboardInterrupt:

        print("\n")
        print("CyberShield collector stopped.")