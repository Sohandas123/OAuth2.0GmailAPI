from flask import Flask, redirect, request, session, url_for, render_template, make_response, send_file
from google_auth_oauthlib.flow import Flow
from googleapiclient.discovery import build
from google.oauth2.credentials import Credentials
from googleapiclient.errors import HttpError
import os
import database
from crypto import generate_aes_key, encrypt_aes, decrypt_aes, encrypt_rsa, decrypt_rsa, encrypt_file, decrypt_file
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.application import MIMEApplication
from email.mime.base import MIMEBase
from email import encoders
import base64
import time
import logging

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'

app = Flask(__name__, static_folder='static')
app.secret_key = os.urandom(24)
app.config['MAX_CONTENT_LENGTH'] = 25 * 1024 * 1024  # 25MB limit

# Configure Google OAuth
CLIENT_SECRETS_FILE = 'client_secret.json'
SCOPES = [
    'https://www.googleapis.com/auth/gmail.send',
    'https://www.googleapis.com/auth/gmail.readonly'
]
REDIRECT_URI = 'http://localhost:5000/callback'
flow = Flow.from_client_secrets_file(
    CLIENT_SECRETS_FILE,
    scopes=SCOPES,
    redirect_uri=REDIRECT_URI
)


def send_email_with_retry(service, message, max_retries=3, initial_delay=1):
    for attempt in range(max_retries):
        try:
            return service.users().messages().send(
                userId='me',
                body={'raw': base64.urlsafe_b64encode(message.as_bytes()).decode()}
            ).execute()
        except HttpError as e:
            if e.resp.status in [500, 503] and attempt < max_retries - 1:
                delay = initial_delay * (2 ** attempt)
                logger.warning(f"Attempt {attempt + 1} failed. Retrying in {delay} seconds...")
                time.sleep(delay)
                continue
            raise

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/login')
def login():
    authorization_url, state = flow.authorization_url()
    session['state'] = state
    return redirect(authorization_url)

@app.route('/callback')
def callback():
    try:
        flow.fetch_token(authorization_response=request.url)
        credentials = flow.credentials
        session['credentials'] = {
            'token': credentials.token,
            'refresh_token': credentials.refresh_token,
            'token_uri': credentials.token_uri,
            'client_id': credentials.client_id,
            'client_secret': credentials.client_secret,
            'scopes': credentials.scopes
        }
        return redirect(url_for('send_mail'))
    except Exception as e:
        logger.error(f"Auth error: {str(e)}")
        return render_template(
            'error.html',
            error=f"Authentication failed: {str(e)}",
            return_page='login',  # Primary recovery
            alt_page='index'     # Fallback
        )

@app.route('/send_mail', methods=['GET', 'POST'])
def send_mail():
    if request.method == 'POST':
        try:
            # 1. Get authenticated user's email
            creds = Credentials(**session['credentials'])
            service = build('gmail', 'v1', credentials=creds)
            user_info = service.users().getProfile(userId='me').execute()
            sender_email = user_info['emailAddress']

            # 2. Process multiple recipients
            recipient_emails = [email.strip() for email in request.form['to'].split(',')]
            if not recipient_emails:
                return render_template('error.html', error="At least one recipient is required!", return_page='send_mail', alt_page='index')

            # 3. Fetch recipients' public keys
            db_session = database.Session()
            recipients = []
            for email in recipient_emails:
                recipient = db_session.query(database.Recipient).filter_by(email=email).first()
                if not recipient:
                    return render_template('error.html', error=f"Recipient not found: {email}", return_page='send_mail', alt_page='index')
                recipients.append(recipient)

            # 4. Generate AES key and encrypt message
            aes_key = generate_aes_key()
            iv, encrypted_data, tag = encrypt_aes(request.form['message'].encode(), aes_key)

            # 5. Build email for each recipient
            for recipient in recipients:
                try:
                    # Encrypt AES key with recipient's public key
                    encrypted_aes_key = encrypt_rsa(aes_key, recipient.public_key)

                    # Create MIME message
                    msg = MIMEMultipart()
                    msg['To'] = recipient.email
                    msg['From'] = sender_email
                    msg['Subject'] = request.form['subject']

                    # Add text part
                    msg.attach(MIMEText("This email contains encrypted attachments. Please use the attached files to decrypt the message.", 'plain'))

                    # Attach encrypted components
                    components = [
                        (encrypted_data, 'message.enc'),
                        (encrypted_aes_key, f'key_{recipient.email[:5]}.enc'),
                        (iv, 'iv.bin'),
                        (tag, 'tag.bin')
                    ]
                    
                    for data, filename in components:
                        part = MIMEApplication(data)
                        part.add_header('Content-Disposition', f'attachment; filename="{filename}"')
                        msg.attach(part)

                    # Handle and encrypt file attachments
                    if 'attachment' in request.files:
                        for file in request.files.getlist('attachment'):
                            if file.filename == '':
                                continue
                                
                            try:
                                # Encrypt the file
                                encrypted_file = encrypt_file(file, file.filename, aes_key)
                                
                                # Attach all three parts
                                attachments = [
                                    (encrypted_file['data'], f"{encrypted_file['original_name']}.enc"),
                                    (encrypted_file['iv'], f"{encrypted_file['original_name']}.iv"),
                                    (encrypted_file['tag'], f"{encrypted_file['original_name']}.tag")
                                ]
                                
                                for data, filename in attachments:
                                    part = MIMEApplication(data)
                                    part.add_header('Content-Disposition', 'attachment', filename=filename)
                                    msg.attach(part)
                                    
                                logger.info(f"Successfully attached {file.filename} as encrypted parts")
                                
                            except Exception as e:
                                logger.error(f"Skipping attachment {file.filename}: {str(e)}")
                                continue

                    # Send email
                    send_email_with_retry(service, msg)
                    logger.info(f"Email successfully sent to {recipient.email}")
                    
                except Exception as e:
                    logger.error(f"Failed to send to {recipient.email}: {str(e)}")
                    continue

            return render_template('success.html', message=f"Emails sent successfully to {len(recipients)} recipients!")

        except Exception as e:
            logger.error(f"Send mail error: {str(e)}")
            return render_template('error.html', error=f"An error occurred: {str(e)}", return_page='send_mail', alt_page='index')

    return render_template('send_mail.html')

@app.route('/decrypt', methods=['GET', 'POST'])
def decrypt():
    if request.method == 'POST':
        try:
            # Load private key
            private_key_file = request.files['private_key']
            private_key_pem = private_key_file.read().decode()
            
            # Load encrypted AES key
            key_file = request.files['key_file']
            encrypted_aes_key = key_file.read()
            
            # Decrypt AES key
            aes_key = decrypt_rsa(encrypted_aes_key, private_key_pem)
            
            # Process message
            decrypted_message = None
            if all(k in request.files for k in ['message_enc', 'message_iv', 'message_tag']):
                decrypted_message = decrypt_aes(
                    request.files['message_iv'].read(),
                    request.files['message_enc'].read(),
                    request.files['message_tag'].read(),
                    aes_key
                ).decode()
            
            # Process attachments
            decrypted_attachments = []
            attachment_count = int(request.form.get('attachment_count', 0))
            
            for i in range(1, attachment_count + 1):
                data_file = request.files.get(f'attachment_{i}_data')
                iv_file = request.files.get(f'attachment_{i}_iv')
                tag_file = request.files.get(f'attachment_{i}_tag')
                
                if all([data_file, iv_file, tag_file]):
                    original_name = os.path.splitext(data_file.filename)[0]
                    decrypted_data = decrypt_aes(
                        iv_file.read(),
                        data_file.read(),
                        tag_file.read(),
                        aes_key
                    )
                    
                    decrypted_attachments.append({
                        'data': base64.b64encode(decrypted_data).decode(),
                        'filename': original_name
                    })
            
            return render_template('decrypt_result.html', 
                                 decrypted_message=decrypted_message,
                                 decrypted_attachments=decrypted_attachments)
            
        except Exception as e:
            return render_template('error.html', error=f"Decryption failed: {str(e)}", return_page='decrypt')
    
    return render_template('decrypt_form.html')


@app.route('/download_decrypted', methods=['POST'])
def download_decrypted():
    try:
        data = request.form.get('data')
        filename = request.form.get('filename', 'decrypted_file')
        
        if not data:
            return "No file data provided", 400
            
        # Create response with file data
        response = make_response(base64.b64decode(data))
        response.headers['Content-Disposition'] = f'attachment; filename="{filename}"'
        response.headers['Content-Type'] = 'application/octet-stream'
        return response
        
    except Exception as e:
        return f"Download failed: {str(e)}", 500



if __name__ == '__main__':
    app.run(debug=True)