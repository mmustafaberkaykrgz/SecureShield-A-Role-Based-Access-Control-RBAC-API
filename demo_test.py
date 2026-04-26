import requests
import json
import base64

BASE_URL = 'http://127.0.0.1:5000'

def print_separator(title):
    print(f"\n{'='*50}\n--- {title} ---\n{'='*50}")

def run_tests():
    print_separator("1. INITIAL SETUP: REGISTERING TEST USERS")
    
    # Register Admin
    resp = requests.post(f"{BASE_URL}/register", json={
        "username": "admin_user",
        "password": "adminpassword123",
        "role": "Admin"
    })
    print(f"Register Admin Response: {resp.status_code} - {resp.text.strip()}")

    # Register Normal User
    resp = requests.post(f"{BASE_URL}/register", json={
        "username": "standard_user",
        "password": "userpassword123",
        "role": "User"
    })
    print(f"Register User Response: {resp.status_code} - {resp.text.strip()}")

    print_separator("2. SUCCESSFUL LOGIN & JWT ISSUANCE")
    
    # Login as normal user
    resp = requests.post(f"{BASE_URL}/login", json={
        "username": "standard_user",
        "password": "userpassword123"
    })
    print(f"Login Response: {resp.status_code}")
    
    if resp.status_code != 200:
        print("Login failed. Cannot proceed.")
        return
        
    token = resp.json().get('token')
    print(f"Received JWT Token:\n{token}\n")

    print_separator("3. ACCESS DENIED TEST: USER ATTEMPTS ADMIN ROUTE (DELETE)")
    
    headers = {"Authorization": f"Bearer {token}"}
    # Attempt to delete the admin user (id=1)
    resp = requests.delete(f"{BASE_URL}/user/1", headers=headers)
    print(f"DELETE /user/1 Response Code: {resp.status_code}")
    print(f"DELETE /user/1 Response Body: {resp.text.strip()}")
    print("-> Expected: 403 Forbidden (Only Admins can delete)")

    print_separator("4. TAMPER TEST: MODIFYING JWT ROLE TO 'Admin'")
    
    # Split token: Header.Payload.Signature
    parts = token.split('.')
    if len(parts) == 3:
        header, payload_b64, signature = parts
        
        # Decode payload
        # Add padding if necessary for base64
        padding_needed = len(payload_b64) % 4
        if padding_needed:
            payload_b64 += '=' * (4 - padding_needed)
            
        payload_json = base64.urlsafe_b64decode(payload_b64).decode('utf-8')
        payload_data = json.loads(payload_json)
        
        print(f"Original Payload: {payload_data}")
        
        # TAMPER: Change role to Admin
        payload_data['role'] = 'Admin'
        print(f"Tampered Payload: {payload_data}")
        
        # Re-encode payload without resigning
        new_payload_json = json.dumps(payload_data).replace(" ", "")
        new_payload_b64 = base64.urlsafe_b64encode(new_payload_json.encode('utf-8')).decode('utf-8').rstrip("=")
        
        tampered_token = f"{header}.{new_payload_b64}.{signature}"
        print(f"\nTampered Token:\n{tampered_token}\n")
        
        # Try to access DELETE route again with tampered token
        tampered_headers = {"Authorization": f"Bearer {tampered_token}"}
        resp = requests.delete(f"{BASE_URL}/user/1", headers=tampered_headers)
        print(f"DELETE /user/1 with Tampered Token Response Code: {resp.status_code}")
        print(f"DELETE /user/1 with Tampered Token Response Body: {resp.text.strip()}")
        print("-> Expected: 401 Invalid Token (Signature verification failed!)")

if __name__ == '__main__':
    try:
        run_tests()
    except requests.exceptions.ConnectionError:
        print("\n[HATA] Sunucuya bağlanılamadı. Lütfen önce 'python app.py' komutu ile sunucuyu başlattığınızdan emin olun.")
