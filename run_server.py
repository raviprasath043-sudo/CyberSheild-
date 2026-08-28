import os
from waitress import serve
from app import app

print("====================================")
print(" 🛡️ CyberShield Production Server")
print("====================================")

port = int(os.environ.get("PORT", 5000))

print("Server running on:")
print(f"http://0.0.0.0:{port}")
print("Press CTRL+C to stop.")
print()

serve(
    app,
    host="0.0.0.0",
    port=port
)