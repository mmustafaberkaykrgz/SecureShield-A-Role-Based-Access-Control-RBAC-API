# SecureShield: Role-Based Access Control (RBAC) API

**Team: TrustGuardians**
- Mustafa Berkay KARAGÖZ - 220208010
- Şeyma BAYRAM - 220208045
- Kerim TAŞKIN - 220208927

This project is a secure backend API built with Flask. It demonstrates a robust authentication flow using **JSON Web Tokens (JWT)** and implements a **Role-Based Access Control (RBAC)** mechanism restricting features based on user roles (Admin vs. User).

## Features
- **Secure Password Storage:** Uses `Flask-Bcrypt` to salt and hash passwords before storing them in a local SQLite database.
- **JWT Authentication:** Issues stateless JWTs upon successful login containing user claims.
- **Role-Based Routing:**
  - `GET /profile`: Accessible by both standard Users and Admins.
  - `DELETE /user/<id>`: Restricted to **Admins only** (Following the Principle of Least Privilege).
- **Token Revocation (Blacklisting):** Invalidates active tokens upon logout to prevent token reuse.
- **Defensive Logging:** Automatically logs unauthorized access attempts (e.g., standard users attempting to delete an account) to a local `security.log` file.

## Technologies Used
- Python 3
- Flask
- PyJWT
- Flask-Bcrypt
- SQLite3

## How to Run Locally

1. Install the required dependencies:
   ```bash
   pip install -r requirements.txt
   ```

2. Start the Flask server:
   ```bash
   python app.py
   ```

3. Open a new terminal and run the automated test script to see the RBAC flow in action:
   ```bash
   python demo_test.py
   ```

## Demonstration Video
[Insert Unlisted YouTube Link Here]

## Project Report
The theoretical questions regarding the necessity of Salting against **Rainbow Table** attacks and the risks of storing sensitive data in **JWT payloads** are answered in the `report.md` file included in this repository.