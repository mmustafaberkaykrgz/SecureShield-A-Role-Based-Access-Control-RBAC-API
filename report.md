# Mini Project II: SecureShield - Brief Report

## Team/Student Details
- **Team Name:** TrustGuardians
- **Team Members:**
  - Mustafa Berkay KARAGÖZ - 220208010
  - Şeyma BAYRAM - 220208045
  - Kerim TAŞKIN - 220208927

---

## 1. Why Salting is Necessary to Prevent "Rainbow Table" Attacks

A **Rainbow Table** is a massive, precomputed database of cryptographic hashes mapped to their original plain-text passwords. Threat actors use these tables to quickly crack a large number of hashed passwords obtained from database leaks. If a database uses basic hashing (such as standard MD5 or SHA-256) without salting, an attacker simply compares the stolen hashes to their rainbow table to instantly reveal common passwords.

**Salting** is the process of generating a unique, random string (the "salt") and attaching it to every password *before* it gets hashed. 

**How salting prevents Rainbow Table attacks:**
1. **Ensures Uniqueness:** Even if two users share the exact same password (e.g., "admin123"), their final stored hashes will look completely different because each gets a unique salt.
2. **Exponentially Increases Computational Cost:** Because each password has a random salt, attackers cannot rely on their pre-built rainbow tables. They would have to compute a new rainbow table for every single unique salt, which demands an impossibly vast amount of storage and processing power. 
By utilizing the `bcrypt` library in this project, salting is handled securely and automatically, rendering traditional rainbow table attacks useless.

---

## 2. The Risks of Storing Sensitive Data Inside a JWT Payload

A JSON Web Token (JWT) is composed of three parts: Header, Payload, and Signature. While the signature is cryptographic and ensures the *integrity* of the token (meaning it prevents tampering), the Payload itself is merely **Base64Url encoded, not encrypted**.

Storing sensitive data—such as plain-text passwords, credit card details, or private financial information—inside a JWT payload carries severe security risks:
1. **Public Readability:** Because the payload is only encoded, anyone who intercepts or acquires the token can easily decode it (for instance, by pasting it into `jwt.io`) and read the contents in plain text.
2. **Client-Side Vulnerabilities:** JWTs are often stored on the client side (e.g., in `localStorage` or `sessionStorage`). If an application suffers from a Cross-Site Scripting (XSS) vulnerability, an attacker can steal the token, decode it, and instantly gain access to the sensitive data.
3. **Unintended Exposure:** Since JWTs are passed back and forth in HTTP headers, the sensitive info inside could inadvertently be captured in server access logs or proxy records, exposing confidential user data.

**Conclusion for this project:** A JWT payload should be strictly limited to essential, non-sensitive identifiers such as a `user_id`, `username`, and authorization `role`. This is perfectly demonstrated in our SecureShield API, which only stores safe identification claims inside the token.
