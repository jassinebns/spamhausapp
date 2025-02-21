from flask import Flask, request, render_template_string
import requests
from supabase import create_client, Client

app = Flask(__name__)

# Supabase configuration
SUPABASE_URL = "https://pmbdilahhlzpcckjdwwm.supabase.co"
SUPABASE_KEY = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6InBtYmRpbGFoaGx6cGNja2pkd3dtIiwicm9sZSI6ImFub24iLCJpYXQiOjE3Mzk3Mjc2NTcsImV4cCI6MjA1NTMwMzY1N30.f2KWxu2G1qBWsI8lqLYdEr7gw5IdUpADXK25p6JfA6o"
supabase: Client = create_client(SUPABASE_URL, SUPABASE_KEY)

# API endpoints
LOGIN_URL = "https://api.spamhaus.org/api/v1/login"
DOMAIN_CHECK_URL = "https://api.spamhaus.org/api/intel/v2/byobject/domain/"

HTML_STRING = '''
<!DOCTYPE html>
<html>
<head>
    <title>Spamhaus Domain Check</title>
    <style>
        body { font-family: Arial, sans-serif; max-width: 800px; margin: 0 auto; padding: 20px; }
        textarea { width: 100%; height: 150px; padding: 10px; margin-bottom: 10px; }
        button { padding: 10px 20px; background: #007bff; color: white; border: none; cursor: pointer; }
        .result { margin-top: 20px; padding: 15px; background: #f8f9fa; border-radius: 4px; }
        .error { color: #dc3545; }
    </style>
</head>
<body>
    <h1>Domain Reputation Check</h1>
    <form method="POST">
        <textarea name="domains" placeholder="Enter domains (one per line)" required></textarea>
        <button type="submit">Check Scores</button>
    </form>
    
    {% if error %}
        <div class="error">{{ error }}</div>
    {% endif %}
    
    {% if results %}
    <div class="results">
        {% for result in results %}
        <div class="result">
            {{ result.domain }}: <strong>{{ result.score }}</strong>
            {% if result.error %}<span class="error">({{ result.error }})</span>{% endif %}
        </div>
        {% endfor %}
    </div>
    {% endif %}
</body>
</html>
'''

def get_spamhaus_credentials():
    """Retrieve credentials from Supabase"""
    try:
        response = supabase.table('api_credentials') \
                         .select('username, password, realm') \
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

@app.route('/', methods=['GET', 'POST'])
def index():
    results = []
    error = None
    
    if request.method == 'POST':
        domains = request.form.get('domains')
        if domains:
            try:
                token = get_auth_token()
                domain_list = [d.strip() for d in domains.split('\n') if d.strip()]
                
                for domain in domain_list:
                    try:
                        result = check_domain(domain, token)
                        results.append({
                            'domain': domain,
                            'score': result.get('score'),
                            'error': None
                        })
                    except Exception as e:
                        results.append({
                            'domain': domain,
                            'score': None,
                            'error': str(e)
                        })
                
            except Exception as e:
                error = f"Error: {str(e)}"
        else:
            error = "Please enter at least one domain"
    
    return render_template_string(HTML_STRING, results=results, error=error)

if __name__ == '__main__':
    app.run(debug=True)
