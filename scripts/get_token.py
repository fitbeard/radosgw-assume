#!/usr/bin/env python3

import requests
import json
import base64
import sys
from urllib.parse import urljoin

def decode_jwt_payload(token):
    """Decode JWT payload without verification (for development only)"""
    try:
        # JWT has 3 parts separated by dots: header.payload.signature
        parts = token.split('.')
        if len(parts) != 3:
            return None
        
        # Decode the payload (second part)
        payload = parts[1]
        # Add padding if needed
        payload += '=' * (4 - len(payload) % 4)
        decoded_bytes = base64.urlsafe_b64decode(payload)
        return json.loads(decoded_bytes.decode('utf-8'))
    except Exception as e:
        print(f"Error decoding JWT: {e}", file=sys.stderr)
        return None

def get_token(provider_url, client_id, client_secret, username, password, scope="openid"):
    """Get access token using Resource Owner Password Credentials Grant"""
    
    token_endpoint = urljoin(provider_url.rstrip('/') + '/', 'protocol/openid-connect/token')
    
    # Prepare request data
    data = {
        'grant_type': 'password',
        'client_id': client_id,
        'client_secret': client_secret,
        'username': username,
        'password': password,
        'scope': scope
    }
    
    headers = {
        'Content-Type': 'application/x-www-form-urlencoded'
    }
    
    try:
        print(f"🔗 Token endpoint: {token_endpoint}", file=sys.stderr)
        print(f"👤 Username: {username}", file=sys.stderr)
        print(f"🔑 Client ID: {client_id}", file=sys.stderr)
        print(f"📋 Scope: {scope}", file=sys.stderr)
        print("", file=sys.stderr)
        
        # Make the request
        response = requests.post(token_endpoint, data=data, headers=headers, verify=False)
        
        if response.status_code == 200:
            token_data = response.json()
            access_token = token_data.get('access_token')
            
            if access_token:
                print("Token obtained successfully!", file=sys.stderr)
                print("", file=sys.stderr)
                
                # Print raw token
                print("RAW ACCESS TOKEN:")
                print(access_token)
                print("")
                
                # Decode and print token info
                print("DECODED TOKEN INFO:", file=sys.stderr)
                payload = decode_jwt_payload(access_token)
                if payload:
                    print(json.dumps(payload, indent=2), file=sys.stderr)
                else:
                    print("Failed to decode token", file=sys.stderr)
                
                print("", file=sys.stderr)
                print("Usage with radosgw-assume:", file=sys.stderr)
                print(f"   export RADOSGW_OIDC_TOKEN='{access_token}'", file=sys.stderr)
                print("   export RADOSGW_OIDC_AUTH_TYPE='token'", file=sys.stderr)
                
                return access_token
            else:
                print(f"No access token in response: {token_data}", file=sys.stderr)
                return None
        else:
            print(f"Token request failed with status {response.status_code}", file=sys.stderr)
            try:
                error_data = response.json()
                print(f"Error: {error_data}", file=sys.stderr)
            except:
                print(f"Error response: {response.text}", file=sys.stderr)
            return None
            
    except requests.exceptions.RequestException as e:
        print(f"Request failed: {e}", file=sys.stderr)
        return None

def main():
    # Configuration - modify these values for your environment
    PROVIDER_URL = "https://keycloak.example.com/realms/myrealm"
    CLIENT_ID = "radosgw-public"  # Use confidential client with secret
    CLIENT_SECRET = ""  # Replace with actual secret
    USERNAME = "username"  # Replace with actual username
    PASSWORD = ""  # Replace with actual password
    SCOPE = "openid"  # Include offline_access for refresh token
    
    if len(sys.argv) > 1:
        if sys.argv[1] in ['-h', '--help']:
            print("Usage: python get_token.py")
            print("")
            print("This script obtains an OIDC token using username/password authentication.")
            print("Edit the script to configure your OIDC provider settings.")
            print("")
            print("Required configuration in script:")
            print("  - PROVIDER_URL: Your OIDC provider URL")
            print("  - CLIENT_ID: Confidential client ID with secret")
            print("  - CLIENT_SECRET: Client secret")
            print("  - USERNAME: Your username")
            print("  - PASSWORD: Your password")
            return
    
    print("🚀 Getting OIDC token using Resource Owner Password Credentials Grant", file=sys.stderr)
    print("", file=sys.stderr)
    
    # Validate configuration
    if CLIENT_SECRET == "your-client-secret-here":
        print("Please configure CLIENT_SECRET in the script", file=sys.stderr)
        sys.exit(1)
    
    if USERNAME == "your-username":
        print("Please configure USERNAME in the script", file=sys.stderr)
        sys.exit(1)
        
    if PASSWORD == "your-password":
        print("Please configure PASSWORD in the script", file=sys.stderr)
        sys.exit(1)
    
    token = get_token(PROVIDER_URL, CLIENT_ID, CLIENT_SECRET, USERNAME, PASSWORD, SCOPE)
    
    if not token:
        sys.exit(1)

if __name__ == "__main__":
    main()
