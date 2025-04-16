# Secure Email Client with Gmail API Using OAuth2.0

A Flask-based application for sending end-to-end encrypted emails using Gmail's API, featuring:
- AES-256 encryption for messages/attachments
- RSA-2048 for secure key exchange
- OAuth2 authentication
- Recipient public key management

## Installation
```bash
git clone https://github.com/Sohandas123/OAuth2.0GmailAPI.git
cd OAuth2.0GmailAPI
python3 -m venv venv
source venv/bin/activate  
pip install -r requirements.txt
```

## Configuration
- Get Google OAuth credentials (client_secret.json)

- Initialize database:
    ```bash
    python3 database.py
    ```
- Generate public private key pairs:
    ```bash
    python3 generate_keys.py
    ```
- Add recipients' public keys to database:
    ```bash
    python3 add_recipient.py
    ```
- Check database:
    ```bash
    python3 check_db.py
    ```

## Usage
- To run the application / software:
    ```bash
    python3 app.py
    ```
- Visit `http://localhost:5000` to:

    - Send encrypted emails

    - Manage recipients

    - Decrypt received messages

## Rate Limits
- 100 emails/day (free tier)

- 20 requests/second/user

- Monitor usage in Google Cloud Console

## Security
Keep in mind at the time of deployment / production:

    ```python
    app.config.update(
        SESSION_COOKIE_SECURE=True,
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE='Lax'
    )
    ```
## Troubleshooting
Common issues:

- 403 Rate Limit Exceeded: Implement exponential backoff

- Key Not Found: Verify recipient's public key in DB

- Attachment Size: Keep <25MB per message

