from flask import Flask, request, render_template_string
from supabase import create_client, Client
import requests
import re
from datetime import datetime

app = Flask(__name__)

# Supabase configuration
SUPABASE_URL = "https://pmbdilahhlzpcckjdwwm.supabase.co"
SUPABASE_KEY = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6InBtYmRpbGFoaGx6cGNja2pkd3dtIiwicm9sZSI6ImFub24iLCJpYXQiOjE3Mzk3Mjc2NTcsImV4cCI6MjA1NTMwMzY1N30.f2KWxu2G1qBWsI8lqLYdEr7gw5IdUpADXK25p6JfA6o"
supabase: Client = create_client(SUPABASE_URL, SUPABASE_KEY)

# API endpoints
LOGIN_URL = "https://api.spamhaus.org/api/v1/login"
DOMAIN_CHECK_URL = "https://api.spamhaus.org/api/intel/v2/byobject/domain/"
IP_CHECK_URL = "https://api.spamhaus.org/api/intel/v1/byobject/cidr/CSS/listed/history/"

HTML_STRING = '''
<!DOCTYPE html>
<html>
<head>
    <title>Spamhaus Checker</title>
    <style>
        body { font-family: Arial, sans-serif; max-width: 800px; margin: 0 auto; padding: 20px; }
        .input-section { margin-bottom: 2rem; }
        textarea { width: 100%; height: 150px; padding: 1rem; margin: 1rem 0; border: 2px solid #ddd; border-radius: 8px; }
        button { background: #007bff; color: white; padding: 0.8rem 1.5rem; border: none; border-radius: 8px; cursor: pointer; }
        .result { background: #f8f9fa; padding: 1.5rem; margin: 1rem 0; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.05); }
        .result h3 { margin-top: 0; color: #2c3e50; }
        .clean { color: #28a745; font-weight: bold; }
        .info-item { margin: 0.5rem 0; }
        .label { color: #6c757d; font-weight: 500; }
        .error { color: #dc3545; }
        .timestamp { color: #6c757d; font-size: 0.9em; }
    </style>
</head>
<body>
    <h1>Spamhaus Reputation Check</h1>
    
    <div class="input-section">
        <form method="POST">
            <textarea 
                name="entries" 
                placeholder="Enter domains or IP addresses (one per line)
Examples:
google.com
8.8.8.8
example.org
104.249.137.173"
            >{% if request.method == 'POST' %}{{ request.form.entries }}{% endif %}</textarea>
            <button type="submit">Check Reputation</button>
        </form>
    </div>

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
                        <span class="label">Risk Score:</span> 
                        <span class="score">{{ result.score }}/10</span>
                    </div>
                {% elif result.type == 'ip' %}
                    {% if result.listed %}
                        <div class="info-item">
                            <span class="label">Dataset:</span> {{ result.dataset }}
                        </div>
                        <div class="info-item">
                            <span class="label">Listed:</span> 
                            <span class="timestamp">{{ result.listed_at|datetime }}</span>
                        </div>
                        <div class="info-item">
                            <span class="label">Valid Until:</span> 
                            <span class="timestamp">{{ result.valid_until|datetime }}</span>
                        </div>
                        <div class="info-item">
                            <span class="label">Detection Method:</span> 
                            {{ result.heuristic }}
                        </div>
                    {% else %}
                        <div class="clean">IP is clean (no active listings)</div>
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

def is_valid_ip(entry):
    """Validate IPv4 address format"""
    ip_pattern = r'^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$'
    return re.match(ip_pattern, entry.strip()) is not None

def get_spamhaus_credentials():
    """Retrieve credentials from Supabase"""
    try:
        response = supabase.table('api_credentials') \
                         .select('username, password') \
                         .execute()
        if not response.data:
            raise ValueError("No credentials found in database")
        return response.data[0]
    except Exception as e:
        raise RuntimeError(f"Failed to fetch credentials: {str(e)}")

def get_auth_token():
    """Authenticate with Spamhaus API and return JWT token"""
    try:
        credentials = get_spamhaus_credentials()
        
        auth_payload = {
            "username": credentials['username'],
            "password": credentials['password'],
            "realm": "intel"
        }
        
        response = requests.post(
            LOGIN_URL,
            json=auth_payload,
            headers={'Content-Type': 'application/json'},
            timeout=10
        )
        response.raise_for_status()
        return response.json()['token']
        
    except Exception as e:
        raise RuntimeError(f"Authentication failed: {str(e)}")

def check_domain(domain, token):
    """Check domain reputation"""
    headers = {'Authorization': f'Bearer {token}'}
    response = requests.get(f"{DOMAIN_CHECK_URL}{domain}", headers=headers)
    response.raise_for_status()
    return response.json()

def check_ip(ip, token):
    """Check IP reputation with expiration validation"""
    headers = {'Authorization': f'Bearer {token}'}
    response = requests.get(f"{IP_CHECK_URL}{ip}", headers=headers)
    
    if response.status_code == 404:
        return {'listed': False}
    
    response.raise_for_status()
    data = response.json()
    
    current_time = datetime.utcnow().timestamp()
    active_listings = []
    
    for listing in data.get('results', []):
        valid_until = listing.get('valid_until', 0)
        if valid_until > current_time:
            active_listings.append({
                'listed_at': listing.get('listed_at'),
                'valid_until': valid_until,
                'heuristic': listing.get('heuristic'),
                'dataset': listing.get('dataset', 'CSS')
            })
    
    if not active_listings:
        return {'listed': False}
    
    # Return first active listing details
    return {
        'listed': True,
        **active_listings[0]
    }

@app.template_filter('datetime')
def format_datetime(timestamp):
    """Convert UNIX timestamp to readable format"""
    if not timestamp:
        return 'N/A'
    return datetime.utcfromtimestamp(timestamp).strftime('%Y-%m-%d %H:%M:%S UTC')

@app.route('/', methods=['GET', 'POST'])
def index():
    results = []
    error = None
    
    if request.method == 'POST':
        entries = request.form.get('entries', '')
        if entries.strip():
            try:
                token = get_auth_token()
                entries_list = [e.strip() for e in entries.split('\n') if e.strip()]
                
                for entry in entries_list:
                    result = {'entry': entry}
                    try:
                        if is_valid_ip(entry):
                            ip_data = check_ip(entry, token)
                            result.update({
                                'type': 'ip',
                                'listed': ip_data['listed'],
                                'listed_at': ip_data.get('listed_at'),
                                'valid_until': ip_data.get('valid_until'),
                                'heuristic': ip_data.get('heuristic'),
                                'dataset': ip_data.get('dataset'),
                                'error': None
                            })
                        else:
                            domain_data = check_domain(entry, token)
                            result.update({
                                'type': 'domain',
                                'score': domain_data.get('score'),
                                'error': None
                            })
                        
                        results.append(result)
                    except requests.HTTPError as e:
                        error_msg = f"API Error: {e.response.status_code}"
                        if e.response.text:
                            error_msg += f" - {e.response.json().get('message', 'Unknown error')}"
                        result['error'] = error_msg
                        results.append(result)
                    except Exception as e:
                        result['error'] = str(e)
                        results.append(result)
            except Exception as e:
                error = f"System Error: {str(e)}"
        else:
            error = "Please enter at least one domain or IP address"
    
    return render_template_string(HTML_STRING, results=results, error=error)

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
