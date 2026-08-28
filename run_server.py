import os
from waitress import serve
from app import app

PORT = int(os.environ.get("PORT", 5000))

print("====================================")
print(" 🛡️ CyberShield Production Server")
print("====================================")
print("Server running at:")
print(f"http://0.0.0.0:{PORT}")
print("Press CTRL+C to stop.")
print()

serve(
    app,
    host="0.0.0.0",
    port=PORT
)