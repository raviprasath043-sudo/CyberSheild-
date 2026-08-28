import sqlite3

DATABASE = "data/security.db"


def get_connection():
    connection = sqlite3.connect(DATABASE)
    connection.row_factory = sqlite3.Row
    return connection


def initialize_database():
    connection = get_connection()

    connection.execute("""
        CREATE TABLE IF NOT EXISTS security_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            event_time TEXT NOT NULL,
            source_ip TEXT NOT NULL,
            event_type TEXT NOT NULL,
            severity TEXT NOT NULL
        )
    """)

    connection.commit()
    connection.close()


def add_event(event_time, source_ip, event_type, severity):
    connection = get_connection()

    connection.execute("""
        INSERT INTO security_events
        (event_time, source_ip, event_type, severity)
        VALUES (?, ?, ?, ?)
    """, (event_time, source_ip, event_type, severity))

    connection.commit()
    connection.close()


def get_events():
    connection = get_connection()

    events = connection.execute("""
        SELECT *
        FROM security_events
        ORDER BY id DESC
    """).fetchall()

    connection.close()

    return events
def clear_events():
    connection = get_connection()

    connection.execute("DELETE FROM security_events")

    connection.commit()
    connection.close()