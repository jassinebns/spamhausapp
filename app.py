from flask import Flask, render_template_string, request, jsonify
import requests
import time
from supabase import create_client

app = Flask(__name__)

# Supabase Configuration
SUPABASE_URL = "https://pmbdilahhlzpcckjdwwm.supabase.co"
SUPABASE_KEY = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6InBtYmRpbGFoaGx6cGNja2pkd3dtIiwicm9sZSI6ImFub24iLCJpYXQiOjE3Mzk3Mjc2NTcsImV4cCI6MjA1NTMwMzY1N30.f2KWxu2G1qBWsI8lqLYdEr7gw5IdUpADXK25p6JfA6o"
supabase = create_client(SUPABASE_URL, SUPABASE_KEY)

supabase = create_client(SUPABASE_URL, SUPABASE_KEY)

response = supabase.table("api_credentials").select("*").execute()
print("📡 Supabase Data:", response.data)

def get_supabase_credentials():
    try:
        result = supabase.table("api_credentials").select("*").execute()
        return result.data[0] if result.data else None
    except Exception as e:
        print(f"Supabase error: {str(e)}")
        return None

def get_spamhaus_token():
    credentials = get_supabase_credentials()
    if not credentials:
        print("🚨 No credentials found in Supabase!")
        return None

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
        response.raise_for_status()
        data = response.json()

        # 🔍 Debugging: Check if token exists and expiration time
        token = data.get("token")
        expires = data.get("expires", 0)
        if not token:
            print("🚨 No token received from Spamhaus API!")
            return None

        print(f"✅ Token received: {token[:20]}... (truncated for security)")
        print(f"⏳ Token expires at: {time.strftime('%Y-%m-%d %H:%M:%S', time.gmtime(expires))}")

        return token
    except Exception as e:
        print(f"🚨 Login failed: {str(e)}")
        return None
    credentials = get_supabase_credentials()
    if not credentials:
        return None

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
        response.raise_for_status()
        return response.json().get("token")
    except Exception as e:
        print(f"Login failed: {str(e)}")
        return None

FRONTEND_HTML = """
<!DOCTYPE html>
<html>
<head>
    <title>Spamhaus Checker</title>
    <style>
        body { font-family: Arial, sans-serif; max-width: 800px; margin: 20px auto; padding: 20px; }
        textarea { width: 100%; height: 150px; margin: 10px 0; }
        button { padding: 10px 20px; background: #007bff; color: white; border: none; border-radius: 4px; cursor: pointer; }
        #results { margin-top: 20px; padding: 15px; background: #f8f9fa; border-radius: 4px; white-space: pre-wrap; }
    </style>
</head>
<body>
    <h1>Spamhaus Blocklist Check</h1>
    <textarea id="inputData" placeholder="Enter IPs/domains (one per line)"></textarea>
    <button id="checkButton">Check Entries</button>
    <div id="results"></div>

    <script>
        function handleCheck() {
            const input = document.getElementById('inputData').value
                .split('\\n')  // Corrected newline splitting
                .map(item => item.trim())
                .filter(item => item.length > 0);

            if (input.length === 0) {
                alert('Please enter at least one valid IP/domain');
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

        // Correct event listener setup
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
    data = request.json.get("data", [])
    token = get_spamhaus_token()

    if not token:
        return jsonify({"error": "Failed to authenticate with Spamhaus API"}), 401

    print(f"🔑 Using Token: {token}")  # Debugging: Check token before sending request

    results = []
    for item in data:
        try:
            response = requests.get(
                f"https://api.spamhaus.org/api/v1/query/{item}",
                headers={"Authorization": f"Bearer {token}"}
            )
            print(f"📡 Request to Spamhaus: {response.url}")  # Debugging
            print(f"📥 Response: {response.status_code}, {response.text}")  # Debugging
            result = response.json()
        except Exception as e:
            result = {"error": str(e)}
        
        results.append({item: result})
    
    return jsonify(results)


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
