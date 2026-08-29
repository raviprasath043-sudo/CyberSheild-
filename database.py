import sqlite3
import os

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.path.join(BASE_DIR, "data")
DATABASE = os.path.join(DATA_DIR, "security.db")


def get_connection():
    os.makedirs(DATA_DIR, exist_ok=True)
    connection = sqlite3.connect(DATABASE)
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