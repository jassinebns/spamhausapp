from flask import Flask, render_template_string, request, jsonify
from supabase import create_client
import requests
import traceback
import re
import time

app = Flask(__name__)

# Configuration
SUPABASE_URL = "https://pmbdilahhlzpcckjdwwm.supabase.co"
SUPABASE_KEY = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6InBtYmRpbGFoaGx6cGNja2pkd3dtIiwicm9sZSI6ImFub24iLCJpYXQiOjE3Mzk3Mjc2NTcsImV4cCI6MjA1NTMwMzY1N30.f2KWxu2G1qBWsI8lqLYdEr7gw5IdUpADXK25p6JfA6o"
supabase = create_client(SUPABASE_URL, SUPABASE_KEY)
session = requests.Session()

# HTML Template with corrected JavaScript
HTML_TEMPLATE = """
<!DOCTYPE html>
<html>
<head>
    <title>Spamhaus Bulk IP Checker</title>
    <style>
        /* ... (keep existing styles) ... */
    </style>
</head>
<body>
    <div class="container">
        <!-- ... (existing HTML structure) ... -->
        <table id="resultsTable">
            <!-- ... (existing table headers) ... -->
            <tbody></tbody>
        </table>
    </div>
    <script>
        function createRow(result) {
            const tr = document.createElement('tr');
            
            const cells = [
                result.ip,
                result.listed ? 'Yes' : 'No',
                result.listed_at ? new Date(result.listed_at * 1000).toLocaleString() : 'N/A',
                result.valid_until ? new Date(result.valid_until * 1000).toLocaleString() : 'N/A',
                result.heuristic || 'N/A'
            ];

            cells.forEach(text => {
                const td = document.createElement('td');
                td.textContent = text;
                tr.appendChild(td);
            });

            return tr;
        }

        async function checkIPs() {
            // ... (existing code) ...
            
            const tbody = document.querySelector('#resultsTable tbody');
            tbody.innerHTML = '';
            data.results.forEach(result => {
                tbody.appendChild(createRow(result));
            });
            // ... (rest of existing code) ...
        }
    </script>
</body>
</html>
"""

def get_spamhaus_token():
    """Retrieve and validate Spamhaus API token"""
    try:
        response = supabase.table("api_credentials").select("*").execute()
        if not response.data:
            raise ValueError("No credentials found in database")
            
        creds = response.data[0]
        required_fields = ['username', 'password']
        for field in required_fields:
            if field not in creds:
                raise ValueError(f"Missing required field: {field}")

        resp = session.post(
            "https://api.spamhaus.org/api/v1/login",
            json={
                "username": creds["username"],  # Corrected field name
                "password": creds["password"],
                "realm": "intel"
            },
            timeout=10
        )
        resp.raise_for_status()
        return resp.json()["token"]
        
    except Exception as e:
        app.logger.error(f"Auth Error: {str(e)}\n{traceback.format_exc()}")
        raise

def is_valid_ip(ip):
    """Validate IPv4 address format"""
    pattern = r"^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$"
    return re.match(pattern, ip) is not None

@app.route('/check_bulk', methods=['POST'])
def check_bulk_ips():
    try:
        data = request.get_json()
        ips = data.get('ips', [])
        
        if not ips or not isinstance(ips, list):
            return jsonify({"error": "Invalid IP list format"}), 400

        token = get_spamhaus_token()
        current_time = time.time()
        results = []

        for ip in ips:
            result = {"ip": ip}
            try:
                if not is_valid_ip(ip):
                    result["error"] = "Invalid IP format"
                    results.append(result)
                    continue

                resp = session.get(
                    f"https://api.spamhaus.org/api/intel/v1/byobject/cidr/ALL/listed/history/{ip}",
                    headers={"Authorization": f"Bearer {token}"},
                    timeout=10
                )

                if resp.status_code == 404:
                    result.update({
                        "listed": False,
                        "listed_at": None,
                        "valid_until": None,
                        "heuristic": None
                    })
                else:
                    resp.raise_for_status()
                    data = resp.json().get("results", [{}])[0]
                    
                    # Determine active listing status
                    valid_until = data.get("valid_until", 0)
                    active = valid_until > current_time
                    
                    result.update({
                        "listed": active,
                        "listed_at": data.get("listed_at"),
                        "valid_until": valid_until if active else None,
                        "heuristic": data.get("heuristic"),
                        "dataset": data.get("dataset")
                    })

            except Exception as e:
                result["error"] = f"Check failed: {str(e)}"
                
            results.append(result)

        return jsonify({"results": results})

    except Exception as e:
        app.logger.error(f"Bulk Check Error: {str(e)}\n{traceback.format_exc()}")
        return jsonify({"error": "Internal server error"}), 500

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
