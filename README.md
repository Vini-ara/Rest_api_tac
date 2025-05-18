# TAC Project - Secure REST API Example

This project is a simple secure REST API built with Python, using JWT authentication (HMAC and RSA), bcrypt password hashing, SQLite database, and HTTPS with a self-signed certificate. It includes a command-line client for authentication and protected resource access.

## Features
- User authentication with JWT (HMAC or RSA algorithms)
- Passwords hashed with bcrypt
- SQLite database for user storage
- HTTPS enabled with self-signed certificate
- Simple Python HTTP server (no frameworks)
- Command-line client for testing authentication and protected endpoints

## Requirements
- Python 3.10+
- OpenSSL (for key/cert generation)
- pip (for installing dependencies)

## Setup
1. **Clone the repository and enter the project folder.**
2. **Install dependencies:**
   ```bash
   pip install -r requirements.txt
   ```
3. **Generate keys and certificates:**
   ```bash
   bash gen_keys.sh
   ```
   This will create the `keys/` directory with:
   - `hmac_secret.key` (HMAC secret)
   - `rsa_private_key.pem` and `rsa_public_key.pem` (RSA keys)
   - `cert_ssl.pem` and `key_ssl.pem` (SSL certificate and key)
4. **Initialize the database (optional):**
   The server will create the `app.db` file and a default admin user on first run.

## Running the Server
```bash
python server.py
```
The server will start on `https://localhost:8000` with SSL enabled.

## Using the Client
Run the client in another terminal:
```bash
python client.py
```
You will see a menu to:
- Authenticate using RSA or HMAC
- Fetch protected data

## Default User
- Username: `admin`
- Password: `admin`

## Notes
- The SSL certificate is self-signed. The client disables certificate verification for testing purposes.
- All keys and secrets are stored in the `keys/` directory (ignored by git).
- For production, use strong secrets, secure key storage, and a trusted SSL certificate.

