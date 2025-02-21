from flask import Flask, request, render_template_string
import requests
from supabase import create_client, Client
import re

app = Flask(__name__)

# Supabase configuration
SUPABASE_URL = "https://pmbdilahhlzpcckjdwwm.supabase.co"
SUPABASE_KEY = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6InBtYmRpbGFoaGx6cGNja2pkd3dtIiwicm9sZSI6ImFub24iLCJpYXQiOjE3Mzk3Mjc2NTcsImV4cCI6MjA1NTMwMzY1N30.f2KWxu2G1qBWsI8lqLYdEr7gw5IdUpADXK25p6JfA6o"
supabase: Client = create_client(SUPABASE_URL, SUPABASE_KEY)

# API endpoints
LOGIN_URL = "https://api.spamhaus.org/api/v1/login"
DOMAIN_CHECK_URL = "https://api.spamhaus.org/api/intel/v2/byobject/domain/"
IP_CHECK_URL = "https://api.spamhaus.org/api/intel/v1/byobject/cidr/all/listed/history/"

HTML_STRING = '''
<!DOCTYPE html>
<html>
<head>
    <title>Spamhaus Checker</title>
    <style>
        body { font-family: Arial, sans-serif; max-width: 800px; margin: 0 auto; padding: 20px; }
        textarea { width: 100%; height: 150px; padding: 10px; margin-bottom: 10px; }
        button { padding: 10px 20px; background: #007bff; color: white; border: none; cursor: pointer; }
        .result { margin-top: 20px; padding: 15px; background: #f8f9fa; border-radius: 4px; }
        .error { color: #dc3545; }
        .clean { color: #28a745; }
        .info-item { margin: 5px 0; }
        .label { font-weight: bold; }
    </style>
</head>
<body>
    <h1>Spamhaus Reputation Check</h1>
    <form method="POST">
        <textarea name="entries" placeholder="Enter domains or IPs (one per line)" required></textarea>
        <button type="submit">Check Reputation</button>
    </form>
    
    {% if error %}
        <div class="error">{{ error }}</div>
    {% endif %}
    
    {% if results %}
    <div class="results">
        {% for result in results %}
        <div class="result">
            <h3>{{ result.entry }}</h3>
            {% if result.error %}
                <div class="error">Error: {{ result.error }}</div>
            {% else %}
                {% if result.type == 'domain' %}
                    <div class="info-item">
                        <span class="label">Risk Score:</span> {{ result.score }}
                    </div>
                {% elif result.type == 'ip' %}
                    {% if result.listed %}
                        <div class="info-item">
                            <span class="label">Listed:</span> {{ result.listed|datetime }}
                        </div>
                        <div class="info-item">
                            <span class="label">Valid Until:</span> {{ result.valid_until|datetime }}
                        </div>
                        <div class="info-item">
                            <span class="label">Heuristic:</span> {{ result.heuristic }}
                        </div>
                    {% else %}
                        <div class="clean">✅ IP is clean (not listed)</div>
                    {% endif %}
                {% endif %}
            {% endif %}
        </div>
        {% endfor %}
    </div>
    {% endif %}
</body>
</html>
'''

def is_ip(entry):
    """Check if an entry is an IP address"""
    ip_pattern = r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$'
    return re.match(ip_pattern, entry) is not None

def get_spamhaus_credentials():
    """Retrieve credentials from Supabase"""
    try:
        response = supabase.table('api_credentials') \
                         .select('email, password, realm') \
                         .execute()
        return response.data[0]
    except Exception as e:
        raise RuntimeError(f"Failed to fetch credentials: {str(e)}")

def get_auth_token():
    """Get authentication token from Spamhaus API"""
    credentials = get_spamhaus_credentials()
    response = requests.post(
        LOGIN_URL,
        json=credentials,
        headers={'Content-Type': 'application/json'}
    )
    response.raise_for_status()
    return response.json().get('token')

def check_domain(domain, token):
    """Check domain reputation"""
    headers = {'Authorization': f'Bearer {token}'}
    response = requests.get(
        f"{DOMAIN_CHECK_URL}{domain}",
        headers=headers
    )
    response.raise_for_status()
    return response.json()

def check_ip(ip, token):
    """Check IP reputation"""
    headers = {'Authorization': f'Bearer {token}'}
    response = requests.get(
        f"{IP_CHECK_URL}{ip}",
        headers=headers
    )
    
    if response.status_code == 404:
        return None  # IP not listed
    response.raise_for_status()
    
    data = response.json()
    return data.get('results', [])[0] if data.get('results') else None

@app.template_filter('datetime')
def datetime_filter(timestamp):
    """Convert UNIX timestamp to readable datetime"""
    from datetime import datetime
    return datetime.utcfromtimestamp(timestamp).strftime('%Y-%m-%d %H:%M:%S UTC')

@app.route('/', methods=['GET', 'POST'])
def index():
    results = []
    error = None
    
    if request.method == 'POST':
        entries = request.form.get('entries')
        if entries:
            try:
                token = get_auth_token()
                entry_list = [e.strip() for e in entries.split('\n') if e.strip()]
                
                for entry in entry_list:
                    result = {'entry': entry}
                    try:
                        if is_ip(entry):
                            # IP Check
                            ip_data = check_ip(entry, token)
                            if ip_data:
                                result.update({
                                    'type': 'ip',
                                    'listed': ip_data.get('listed'),
                                    'valid_until': ip_data.get('valid_until'),
                                    'heuristic': ip_data.get('heuristic'),
                                    'error': None
                                })
                            else:
                                result.update({
                                    'type': 'ip',
                                    'listed': None,
                                    'valid_until': None,
                                    'heuristic': None,
                                    'error': None
                                })
                        else:
                            # Domain Check
                            domain_data = check_domain(entry, token)
                            result.update({
                                'type': 'domain',
                                'score': domain_data.get('score'),
                                'error': None
                            })
                        
                        results.append(result)
                    except Exception as e:
                        results.append({
                            'entry': entry,
                            'error': str(e)
                        })
                
            except Exception as e:
                error = f"Error: {str(e)}"
        else:
            error = "Please enter at least one entry"
    
    return render_template_string(HTML_STRING, results=results, error=error)

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
