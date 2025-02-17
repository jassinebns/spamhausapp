from flask import Flask, render_template_string, request, jsonify
import requests
import time
from supabase import create_client

app = Flask(__name__)

# Supabase Configuration
SUPABASE_URL = "https://pmbdilahhlzpcckjdwwm.supabase.co"
SUPABASE_KEY = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6InBtYmRpbGFoaGx6cGNja2pkd3dtIiwicm9sZSI6ImFub24iLCJpYXQiOjE3Mzk3Mjc2NTcsImV4cCI6MjA1NTMwMzY1N30.f2KWxu2G1qBWsI8lqLYdEr7gw5IdUpADXK25p6JfA6o"
supabase = create_client(SUPABASE_URL, SUPABASE_KEY)

# ✅ Debugging Supabase Connection
@app.route("/debug_supabase")
def debug_supabase():
    credentials = get_supabase_credentials()
    return jsonify({"retrieved_credentials": credentials})


def get_supabase_credentials():
    """Fetch API credentials from Supabase."""
    try:
        result = supabase.table("api_credentials").select("*").execute()
        print("📡 Supabase Response:", result.data)  # Debugging
        return result.data[0] if result.data else None
    except Exception as e:
        print(f"🚨 Supabase Error: {str(e)}")
        return None


def get_spamhaus_token():
    """Authenticate with Spamhaus API and retrieve an access token."""
    credentials = get_supabase_credentials()
    if not credentials:
        print("🚨 No credentials found in Supabase!")
        return None

    print(f"🔑 Retrieved Credentials: {credentials}")  # Debugging

    try:
        response = requests.post(
            "https://api.spamhaus.org/api/v1/login",
            json={
                "username": credentials["email"],
                "password": credentials["password"],
                "realm": credentials.get("realm", "intel")
            },
            timeout=10
        )
        print(f"📡 Spamhaus API Response: {response.status_code}, {response.text}")  # Debugging
        response.raise_for_status()
        return response.json().get("token")
    except Exception as e:
        print(f"🚨 Login failed: {str(e)}")
        return None


FRONTEND_HTML = """
<!DOCTYPE html>
<html>
<head>
    <title>Spamhaus IP Checker</title>
    <style>
        body { font-family: Arial, sans-serif; max-width: 800px; margin: 20px auto; padding: 20px; }
        textarea { width: 100%; height: 150px; margin: 10px 0; }
        button { padding: 10px 20px; background: #007bff; color: white; border: none; border-radius: 4px; cursor: pointer; }
        #results { margin-top: 20px; padding: 15px; background: #f8f9fa; border-radius: 4px; white-space: pre-wrap; }
    </style>
</head>
<body>
    <h1>Spamhaus IP Blocklist Check</h1>
    <textarea id="inputData" placeholder="Enter IPs (one per line)"></textarea>
    <button id="checkButton">Check IPs</button>
    <div id="results"></div>

    <script>
        function handleCheck() {
            const input = document.getElementById('inputData').value
                .split('\\n')
                .map(item => item.trim())
                .filter(item => item.length > 0);

            if (input.length === 0) {
                alert('Please enter at least one valid IP');
                return;
            }

            fetch('/check', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ data: input })
            })
            .then(response => {
                if (!response.ok) throw new Error(`HTTP error! Status: ${response.status}`);
                return response.json();
            })
            .then(data => {
                document.getElementById('results').textContent = JSON.stringify(data, null, 2);
            })
            .catch(error => {
                document.getElementById('results').textContent = `Error: ${error.message}`;
            });
        }

        document.getElementById('checkButton').addEventListener('click', handleCheck);
    </script>
</body>
</html>
"""


@app.route("/")
def home():
    return render_template_string(FRONTEND_HTML)


@app.route("/check", methods=["POST"])
def check_data():
    """Check if IPs are listed on Spamhaus blocklists."""
    data = request.json.get("data", [])
    token = get_spamhaus_token()

    if not token:
        return jsonify({"error": "Failed to authenticate with Spamhaus API"}), 401

    print(f"🔑 Using Token: {token[:20]}...")  # Debugging

    results = []
    for ip in data:
        try:
            response = requests.get(
                f"https://api.spamhaus.org/api/intel/v1/byobject/cidr/all/listed/history/{ip}",
                headers={"Authorization": f"Bearer {token}"}
            )
            print(f"📡 Request to Spamhaus: {response.url}")  # Debugging
            print(f"📥 Response: {response.status_code}, {response.text}")  # Debugging
            response.raise_for_status()
            result = response.json()
        except Exception as e:
            result = {"error": str(e)}

        results.append({ip: result})

    return jsonify(results)


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
