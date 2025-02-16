from flask import Flask, render_template_string, request, jsonify
import requests
import time
from supabase import create_client

app = Flask(__name__)

# Supabase Configuration
SUPABASE_URL = "https://pmbdilahhlzpcckjdwwm.supabase.co"
SUPABASE_KEY = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6InBtYmRpbGFoaGx6cGNja2pkd3dtIiwicm9sZSI6ImFub24iLCJpYXQiOjE3Mzk3Mjc2NTcsImV4cCI6MjA1NTMwMzY1N30.f2KWxu2G1qBWsI8lqLYdEr7gw5IdUpADXK25p6JfA6o"
supabase = create_client(SUPABASE_URL, SUPABASE_KEY)

# Token caching
cached_token = None
token_expiry = 0

def get_supabase_credentials():
    try:
        result = supabase.table("api_credentials").select("*").execute()
        if not result.data:
            print("🚨 No credentials found in Supabase")
            return None
        return result.data[0]
    except Exception as e:
        print(f"Supabase error: {str(e)}")
        return None

def get_spamhaus_token():
    global cached_token, token_expiry

    # Use cached token if still valid (with 60s buffer)
    if cached_token and time.time() < token_expiry - 60:
        print("♻️ Using cached token")
        return cached_token

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
        data = response.json()

        token = data.get("token")
        expires = data.get("expires", 0)
        if not token:
            print("🚨 No token received from Spamhaus API!")
            return None

        print(f"✅ Token received: {token[:5]}... (truncated)")
        print(f"⏳ Token expires at: {time.strftime('%Y-%m-%d %H:%M:%S', time.gmtime(expires))}")

        # Update cache
        cached_token = token
        token_expiry = expires
        return token
    except Exception as e:
        print(f"🚨 Login failed: {str(e)}")
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
        .loading { display: none; color: #666; font-style: italic; }
    </style>
</head>
<body>
    <h1>Spamhaus Blocklist Check</h1>
    <textarea id="inputData" placeholder="Enter IPs/domains (one per line)"></textarea>
    <button id="checkButton">Check Entries</button>
    <div class="loading" id="loading">Checking... Please wait</div>
    <div id="results"></div>

    <script>
        function handleCheck() {
            const input = document.getElementById('inputData').value
                .split('\\n')
                .map(item => item.trim())
                .filter(item => item.length > 0);

            if (input.length === 0) {
                alert('Please enter at least one valid IP/domain');
                return;
            }

            const resultsDiv = document.getElementById('results');
            const loadingDiv = document.getElementById('loading');
            
            loadingDiv.style.display = 'block';
            resultsDiv.textContent = '';

            fetch('/check', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ data: input })
            })
            .then(response => {
                loadingDiv.style.display = 'none';
                if (!response.ok) throw new Error(`HTTP error! Status: ${response.status}`);
                return response.json();
            })
            .then(data => {
                resultsDiv.textContent = JSON.stringify(data, null, 2);
            })
            .catch(error => {
                resultsDiv.textContent = `Error: ${error.message}`;
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
    data = request.json.get("data", [])
    token = get_spamhaus_token()

    if not token:
        return jsonify({"error": "Failed to authenticate with Spamhaus API"}), 401

    print(f"🔑 Using Token: {token[:5]}...")  # Securely truncated

    results = []
    for item in data:
        entry_result = {}
        try:
            response = requests.get(
                f"https://api.spamhaus.org/api/v1/query/{item}",
                headers={"Authorization": f"Bearer {token}"},
                timeout=10
            )
            
            if response.status_code == 401:
                # Invalidate cached token
                global cached_token, token_expiry
                cached_token = None
                token_expiry = 0
                entry_result[item] = {"error": "Authentication expired, please retry"}
            elif response.status_code != 200:
                entry_result[item] = {"error": f"API returned status {response.status_code}"}
            else:
                entry_result[item] = response.json()
        except requests.exceptions.Timeout:
            entry_result[item] = {"error": "Request timed out"}
        except Exception as e:
            entry_result[item] = {"error": str(e)}
        
        results.append(entry_result)
    
    return jsonify(results)

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
