from database import initialize_database, add_event, clear_events


initialize_database()

# Remove previous test data
clear_events()


events = [
    ("18:30:21", "192.168.1.15", "Failed SSH Login", "HIGH"),

    ("18:30:10", "192.168.1.50", "Failed SSH Login", "HIGH"),
    ("18:30:05", "192.168.1.50", "Failed SSH Login", "HIGH"),
    ("18:29:59", "192.168.1.50", "Failed SSH Login", "HIGH"),

    ("18:29:43", "192.168.1.22", "Port Scan Detected", "CRITICAL"),

    ("18:28:17", "192.168.1.40", "Successful Login", "LOW"),

    ("18:26:31", "192.168.1.22", "Multiple Connection Attempts", "HIGH"),
]


for event in events:
    add_event(*event)


print("Database reset and test events added successfully.")
