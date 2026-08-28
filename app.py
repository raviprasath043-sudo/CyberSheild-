from flask import Flask, render_template, request, jsonify
import os
import ipaddress

from database import (
    initialize_database,
    get_events,
    add_event
)

from detection import analyze_events


app = Flask(__name__)

initialize_database()


# =========================================
# Dashboard
# =========================================

@app.route("/")
def dashboard():

    events = get_events()

    alerts = analyze_events(events)

    return render_template(
        "dashboard.html",
        events=events,
        alerts=alerts
    )


# =========================================
# Real-Time Event Ingestion API
# =========================================

@app.route("/api/events", methods=["POST"])
def receive_event():

    # -----------------------------------------
    # Check JSON request
    # -----------------------------------------

    if not request.is_json:

        return jsonify({
            "success": False,
            "error": "Content-Type must be application/json"
        }), 415

    data = request.get_json(silent=True)

    if not isinstance(data, dict):

        return jsonify({
            "success": False,
            "error": "Valid JSON object required"
        }), 400


    # -----------------------------------------
    # Required fields
    # -----------------------------------------

    required_fields = [
        "event_time",
        "source_ip",
        "event_type",
        "severity"
    ]

    missing_fields = [
        field
        for field in required_fields
        if field not in data
        or data[field] is None
        or data[field] == ""
    ]

    if missing_fields:

        return jsonify({
            "success": False,
            "error": "Missing required fields",
            "fields": missing_fields
        }), 400


    # -----------------------------------------
    # Validate field types
    # -----------------------------------------

    for field in required_fields:

        if not isinstance(data[field], str):

            return jsonify({
                "success": False,
                "error": f"{field} must be a string"
            }), 400


    # -----------------------------------------
    # Validate field lengths
    # -----------------------------------------

    if len(data["event_time"]) > 100:

        return jsonify({
            "success": False,
            "error": "event_time is too long"
        }), 400


    if len(data["source_ip"]) > 45:

        return jsonify({
            "success": False,
            "error": "source_ip is too long"
        }), 400


    if len(data["event_type"]) > 100:

        return jsonify({
            "success": False,
            "error": "event_type is too long"
        }), 400


    if len(data["severity"]) > 20:

        return jsonify({
            "success": False,
            "error": "severity is too long"
        }), 400


    # -----------------------------------------
    # Validate IP address
    # -----------------------------------------

    try:

        ipaddress.ip_address(
            data["source_ip"]
        )

    except ValueError:

        return jsonify({
            "success": False,
            "error": "Invalid source IP address"
        }), 400


    # -----------------------------------------
    # Validate severity
    # -----------------------------------------

    allowed_severities = {
        "LOW",
        "MEDIUM",
        "HIGH",
        "CRITICAL"
    }

    if data["severity"].upper() not in allowed_severities:

        return jsonify({
            "success": False,
            "error": "Invalid severity",
            "allowed": sorted(
                allowed_severities
            )
        }), 400


    # -----------------------------------------
    # Store event
    # -----------------------------------------

    add_event(
        data["event_time"],
        data["source_ip"],
        data["event_type"],
        data["severity"].upper()
    )


    # -----------------------------------------
    # Success response
    # -----------------------------------------

    return jsonify({
        "success": True,
        "message": "Security event received successfully"
    }), 201


# =========================================
# API: Get Events
# =========================================

@app.route("/api/events", methods=["GET"])
def get_event_api():

    events = get_events()

    return jsonify([
        dict(event)
        for event in events
    ])


# =========================================
# Application Start
# =========================================

if __name__ == "__main__":

    host = os.environ.get(
        "HOST",
        "0.0.0.0"
    )

    port = int(
        os.environ.get(
            "PORT",
            5000
        )
    )

    app.run(
        host=host,
        port=port,
        debug=False
    )