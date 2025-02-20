from flask import Flask, render_template_string, request, jsonify
import requests
from supabase import create_client
import datetime

app = Flask(__name__)

# Supabase Configuration
SUPABASE_URL = "https://pmbdilahhlzpcckjdwwm.supabase.co"
SUPABASE_KEY = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6InBtYmRpbGFoaGx6cGNja2pkd3dtIiwicm9sZSI6ImFub24iLCJpYXQiOjE3Mzk3Mjc2NTcsImV4cCI6MjA1NTMwMzY1N30.f2KWxu2G1qBWsI8lqLYdEr7gw5IdUpADXK25p6JfA6o"  # Replace with your actual Supabase key
supabase = create_client(SUPABASE_URL, SUPABASE_KEY)

# Function to fetch API credentials from Supabase
def get_supabase_credentials():
    try:
        result = supabase.table("api_credentials").select("*").execute()
        return result.data[0] if result.data else None
    except Exception as e:
        print(f"🚨 Supabase Error: {str(e)}")
        return None

# Function to get Spamhaus authentication token
def get_spamhaus_token():
    credentials = get_supabase_credentials()
    if not credentials:
        return None
    try:
        response = requests.post(
            "https://api.spamhaus.org/api/v1/login",
            json={
                "username": credentials["username"],  # Ensure this matches your Supabase table
                "password": credentials["password"],
                "realm": credentials.get("realm", "intel")
            },
            timeout=10
        )
        response.raise_for_status()
        return response.json().get("token")
    except Exception as e:
        print(f"🚨 Login failed: {str(e)}")
        return None

# Frontend HTML with table structure
FRONTEND_HTML = """
<!DOCTYPE html>
<html>
<head>
    <title>Spamhaus IP Checker</title>
    <style>
        body { font-family: Arial, sans-serif; max-width: 800px; margin: 20px auto; padding: 20px; }
        textarea { width: 100%; height: 150px; margin: 10px 0; }
        button { padding: 10px 20px; background: #007bff; color: white; border: none; border-radius: 4px; cursor: pointer; }
        table { width: 100%; border-collapse: collapse; margin-top: 20px; }
        th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }
        th { background-color: #007bff; color: white; }
    </style>
</head>
<body>
    <h1>Spamhaus IP Blocklist Check</h1>
    <textarea id="inputData" placeholder="Enter IPs (one per line)"></textarea>
    <button id="checkButton">Check IPs</button>
    <table id="resultsTable" style="display:none;">
        <thead>
            <tr>
                <th>IP Address</th>
                <th>Listed</th>
                <th>Valid Until</th>
                <th>Heuristic</th>
            </tr>
        </thead>
        <tbody></tbody>
    </table>
    <script>
        document.getElementById('checkButton').addEventListener('click', function() {
            const input = document.getElementById('inputData').value
                .split('\n')
                .map(ip => ip.trim())
                .filter(ip => ip.length > 0);
            if (input.length === 0) {
                alert('Please enter at least one valid IP');
                return;
            }
            fetch('/check', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ data: input })
            })
            .then(response => response.json())
            .then(data => {
                const table = document.getElementById('resultsTable');
                const tbody = table.querySelector('tbody');
                tbody.innerHTML = '';
                data.forEach(result => {
                    for (const [ip, details] of Object.entries(result)) {
                        if (details.results && details.results.length > 0) {
                            details.results.forEach(entry => {
                                const row = document.createElement('tr');
                                row.innerHTML = `<td>${ip}</td>
                                                 <td>${entry.listed ? new Date(entry.listed * 1000).toLocaleString() : 'N/A'}</td>
                                                 <td>${entry.valid_until ? new Date(entry.valid_until * 1000).toLocaleString() : 'N/A'}</td>
                                                 <td>${entry.heuristic || 'N/A'}</td>`;
                                tbody.appendChild (row);
                            });
                        } else {
                            const row = document.createElement('tr');
                            row.innerHTML = `<td>${ip}</td>
                                             <td colspan="3">No results found</td>`;
                            tbody.appendChild(row);
                        }
                    }
                });
                table.style.display = 'table';
            })
            .catch(error => console.error('Error:', error));
        });
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

    results = []
    for ip in data:
        try:
            response = requests.get(
                f"https://api.spamhaus.org/api/intel/v1/byobject/cidr/all/listed/history/{ip}",
                headers={"Authorization": f"Bearer {token}"}
            )
            response.raise_for_status()
            result = response.json()
            parsed_result = {
                ip: {
                    "results": [{
                        "listed": entry['listed'],
                        "valid_until": entry['valid_until'],
                        "heuristic": entry.get('heuristic', 'N/A')
                    } for entry in result.get('results', [])]
                }
            }
        except Exception as e:
            parsed_result = {ip: {"error": str(e)}}
        results.append(parsed_result)

    return jsonify(results)

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
