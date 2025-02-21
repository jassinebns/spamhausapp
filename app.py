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

def get_spamhaus_credentials():
    """Retrieve Spamhaus credentials from Supabase"""
    try:
        response = supabase.table('api_credentials')\
                        .select('username, password, realm')\
                        .execute()
        if not response.data:
            raise ValueError("No credentials found in database")
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

# Rest of the Flask app remains the same as previous version
# (HTML_STRING and other functions stay unchanged)

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
                            'error': str(e).replace("'", "")[:50]
                        })
                
            except Exception as e:
                error = f"Authentication Error: {str(e)}"
        else:
            error = "Please enter at least one domain"
    
    return render_template_string(HTML_STRING, results=results, error=error)

if __name__ == '__main__':
    app.run(debug=True)
