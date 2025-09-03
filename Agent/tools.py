import os
import json
import base64
import logging
import hashlib
import secrets
import webbrowser
import threading
import socket
from typing import Optional, Dict, List, Any
from datetime import datetime, timedelta
from pathlib import Path
from dataclasses import dataclass
from urllib.parse import urlparse, parse_qs
from http.server import HTTPServer, BaseHTTPRequestHandler

from tavily import TavilyClient
from google.auth.transport.requests import Request
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError
from Agent.api_keys import TAVILY_API_KEY
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('app.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

# Security configuration
@dataclass
class SecurityConfig:
    MAX_EMAIL_SIZE: int = 10_000_000  # 10MB
    MAX_SEARCH_RESULTS: int = 50
    MAX_CALENDAR_RESULTS: int = 100
    TOKEN_ROTATION_DAYS: int = 30
    RATE_LIMIT_PER_HOUR: int = 1000

SECURITY = SecurityConfig()

# Google API scopes with principle of least privilege
CALENDAR_SCOPES = ['https://www.googleapis.com/auth/calendar']
GMAIL_SCOPES = ['https://www.googleapis.com/auth/gmail.modify']

class SecureCredentialManager:
    """Manages encrypted storage of credentials."""
    
    def __init__(self, password: str = None):
        self.script_dir = Path(__file__).parent
        self.password = password or os.environ.get('CREDENTIAL_PASSWORD', self._generate_password())
        self.key = self._derive_key()
        self.cipher = Fernet(self.key)
    
    def _generate_password(self) -> str:
        """Generate a secure random password."""
        return secrets.token_urlsafe(32)
    
    def _derive_key(self) -> bytes:
        """Derive encryption key from password."""
        password_bytes = self.password.encode('utf-8')
        salt = b'stable_salt'  # In production, use a unique salt per user
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
        )
        return base64.urlsafe_b64encode(kdf.derive(password_bytes))
    
    def encrypt_token(self, token_data: str) -> bytes:
        """Encrypt token data."""
        return self.cipher.encrypt(token_data.encode('utf-8'))
    
    def decrypt_token(self, encrypted_data: bytes) -> str:
        """Decrypt token data."""
        return self.cipher.decrypt(encrypted_data).decode('utf-8')
    
    def save_credentials(self, creds: Credentials, service_name: str):
        """Save encrypted credentials."""
        token_path = self.script_dir / f'{service_name}_token.enc'
        encrypted_data = self.encrypt_token(creds.to_json())
        
        with open(token_path, 'wb') as f:
            f.write(encrypted_data)
        
        # Set restrictive permissions
        os.chmod(token_path, 0o600)
        logger.info(f"Credentials saved for {service_name}")
    
    def load_credentials(self, service_name: str, scopes: List[str]) -> Optional[Credentials]:
        """Load encrypted credentials."""
        token_path = self.script_dir / f'{service_name}_token.enc'
        
        if not token_path.exists():
            return None
        
        try:
            with open(token_path, 'rb') as f:
                encrypted_data = f.read()
            
            decrypted_data = self.decrypt_token(encrypted_data)
            creds = Credentials.from_authorized_user_info(json.loads(decrypted_data), scopes)
            
            # Check if credentials need rotation
            if self._needs_rotation(creds):
                logger.warning(f"Credentials for {service_name} need rotation")
            
            return creds
        except Exception as e:
            logger.error(f"Failed to load credentials for {service_name}: {e}")
            return None
    
    def _needs_rotation(self, creds: Credentials) -> bool:
        """Check if credentials need rotation based on age."""
        # This is a simplified check - in production, implement proper token age tracking
        return False

class InputValidator:
    """Validates and sanitizes user inputs."""
    
    @staticmethod
    def validate_email_address(email: str) -> bool:
        """Validate email address format."""
        import re
        pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        return bool(re.match(pattern, email)) and len(email) <= 254
    
    @staticmethod
    def sanitize_string(input_str: str, max_length: int = 1000) -> str:
        """Sanitize string input."""
        if not isinstance(input_str, str):
            return ""
        
        # Remove null bytes and control characters
        sanitized = ''.join(char for char in input_str if ord(char) >= 32 or char in '\n\r\t')
        return sanitized[:max_length].strip()
    
    @staticmethod
    def validate_query_params(query: str, max_results: int) -> tuple:
        """Validate search query parameters."""
        clean_query = InputValidator.sanitize_string(query, 500)
        safe_max_results = min(max(1, max_results), SECURITY.MAX_SEARCH_RESULTS)
        return clean_query, safe_max_results

class OAuthCallbackHandler(BaseHTTPRequestHandler):
    """Handle OAuth callback with a nice web page."""
    
    def do_GET(self):
        """Handle GET request from OAuth callback."""
        try:
            parsed_path = urlparse(self.path)
            query_params = parse_qs(parsed_path.query)
            
            if 'code' in query_params:
                # Success page
                self.send_response(200)
                self.send_header('Content-type', 'text/html')
                self.end_headers()
                
                success_page = """
                <!DOCTYPE html>
                <html lang="en">
                <head>
                    <meta charset="UTF-8">
                    <meta name="viewport" content="width=device-width, initial-scale=1.0">
                    <title>Authentication Successful</title>
                    <style>
                        body {
                            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
                            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                            margin: 0;
                            padding: 0;
                            display: flex;
                            justify-content: center;
                            align-items: center;
                            min-height: 100vh;
                        }
                        .container {
                            background: white;
                            border-radius: 20px;
                            padding: 40px;
                            box-shadow: 0 20px 40px rgba(0,0,0,0.1);
                            text-align: center;
                            max-width: 400px;
                            width: 90%;
                        }
                        .success-icon {
                            width: 80px;
                            height: 80px;
                            background: #4CAF50;
                            border-radius: 50%;
                            display: flex;
                            align-items: center;
                            justify-content: center;
                            margin: 0 auto 20px;
                            color: white;
                            font-size: 40px;
                        }
                        h1 {
                            color: #333;
                            margin-bottom: 10px;
                            font-size: 24px;
                        }
                        p {
                            color: #666;
                            line-height: 1.6;
                            margin-bottom: 30px;
                        }
                        .close-btn {
                            background: #667eea;
                            color: white;
                            border: none;
                            padding: 12px 24px;
                            border-radius: 8px;
                            font-size: 16px;
                            cursor: pointer;
                            transition: background 0.3s;
                        }
                        .close-btn:hover {
                            background: #5a6fd8;
                        }
                        .google-logo {
                            width: 24px;
                            height: 24px;
                            margin-right: 10px;
                            vertical-align: middle;
                        }
                    </style>
                </head>
                <body>
                    <div class="container">
                        <div class="success-icon">✓</div>
                        <h1>🎉 Authentication Successful!</h1>
                        <p>
                            <img src="data:image/svg+xml;base64,PHN2ZyB3aWR0aD0iMjQiIGhlaWdodD0iMjQiIHZpZXdCb3g9IjAgMCAyNCAyNCIgZmlsbD0ibm9uZSIgeG1sbnM9Imh0dHA6Ly93d3cudzMub3JnLzIwMDAvc3ZnIj4KPHBhdGggZD0iTTIyLjU2IDEyLjI1QzIyLjU2IDExLjQ3IDIyLjQ5IDEwLjcyIDIyLjM2IDEwSDE2djQuNDJoNS45MmMtLjI2IDEuMzctMS4wNCAyLjUzLTIuMjEgMy4zMXYyLjc5aDMuNTdDMjEuMTEgMTguNDQgMjIuNTYgMTUuNiAyMi41NiAxMi4yNVoiIGZpbGw9IiM0Mjg1RjQiLz4KPHBhdGggZD0iTTE2IDI0QzIwLjQzIDI0IDI0IDE5LjM3IDI0IDE0QzI0IDEzLjY4IDIzLjk4IDEzLjM2IDIzLjkzIDEzSDEzdjUuNzJoNC42N0MxNy4xMyAyMC4yIDIwIDIxIDIxIDIzSDI0VjI0SDE2WiIgZmlsbD0iIzM0QTg1MyIvPgo8cGF0aCBkPSJNMTYgMjRDMTIuMDkgMjQgOC43OCAyMC44OSA3LjUxIDEzSDExVjEwSDdDNS41OSAxMC4wOCA0LjQ2IDguNzMgNCA4SDJWMTBINEMzLjU5IDEwIDQgMTAuMjMgNy41MSAxM1oiIGZpbGw9IiNGQkJDMDUiLz4KPHA+PC9wPgo8L3N2Zz4K" class="google-logo" alt="Google">
                            You have successfully connected your Google account. 
                            You can now close this window and return to the application.
                        </p>
                        <button class="close-btn" onclick="window.close()">Close Window</button>
                        <script>
                            // Auto-close after 5 seconds
                            setTimeout(() => {
                                window.close();
                            }, 5000);
                        </script>
                    </div>
                </body>
                </html>
                """
                self.wfile.write(success_page.encode())
                
                # Store the authorization code for the main thread
                self.server.auth_code = query_params['code'][0]
                
            elif 'error' in query_params:
                # Error page
                self.send_response(400)
                self.send_header('Content-type', 'text/html')
                self.end_headers()
                
                error_page = """
                <!DOCTYPE html>
                <html lang="en">
                <head>
                    <meta charset="UTF-8">
                    <meta name="viewport" content="width=device-width, initial-scale=1.0">
                    <title>Authentication Error</title>
                    <style>
                        body {
                            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
                            background: linear-gradient(135deg, #ff6b6b 0%, #ee5a52 100%);
                            margin: 0;
                            padding: 0;
                            display: flex;
                            justify-content: center;
                            align-items: center;
                            min-height: 100vh;
                        }
                        .container {
                            background: white;
                            border-radius: 20px;
                            padding: 40px;
                            box-shadow: 0 20px 40px rgba(0,0,0,0.1);
                            text-align: center;
                            max-width: 400px;
                            width: 90%;
                        }
                        .error-icon {
                            width: 80px;
                            height: 80px;
                            background: #f44336;
                            border-radius: 50%;
                            display: flex;
                            align-items: center;
                            justify-content: center;
                            margin: 0 auto 20px;
                            color: white;
                            font-size: 40px;
                        }
                        h1 {
                            color: #333;
                            margin-bottom: 10px;
                            font-size: 24px;
                        }
                        p {
                            color: #666;
                            line-height: 1.6;
                            margin-bottom: 30px;
                        }
                        .retry-btn {
                            background: #ff6b6b;
                            color: white;
                            border: none;
                            padding: 12px 24px;
                            border-radius: 8px;
                            font-size: 16px;
                            cursor: pointer;
                            transition: background 0.3s;
                        }
                        .retry-btn:hover {
                            background: #ee5a52;
                        }
                    </style>
                </head>
                <body>
                    <div class="container">
                        <div class="error-icon">✗</div>
                        <h1>Authentication Failed</h1>
                        <p>There was an error authenticating with Google. Please try again.</p>
                        <button class="retry-btn" onclick="window.close()">Close Window</button>
                    </div>
                </body>
                </html>
                """
                self.wfile.write(error_page.encode())
                self.server.auth_error = query_params['error'][0]
                
        except Exception as e:
            logger.error(f"OAuth callback error: {e}")
            self.send_response(500)
            self.end_headers()
    
    def log_message(self, format, *args):
        """Suppress default logging."""
        pass

class SecureGoogleService:
    """Secure wrapper for Google services with popup authentication."""
    
    def __init__(self):
        self.credential_manager = SecureCredentialManager()
        self._rate_limiter = {}  # Simple rate limiting storage
    
    def _check_rate_limit(self, service_name: str) -> bool:
        """Simple rate limiting check."""
        now = datetime.now()
        hour_key = now.strftime("%Y%m%d%H")
        key = f"{service_name}_{hour_key}"
        
        current_count = self._rate_limiter.get(key, 0)
        if current_count >= SECURITY.RATE_LIMIT_PER_HOUR:
            logger.warning(f"Rate limit exceeded for {service_name}")
            return False
        
        self._rate_limiter[key] = current_count + 1
        return True
    
    def _find_free_port(self) -> int:
        """Find a free port for the OAuth callback server."""
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.bind(('', 0))
            s.listen(1)
            port = s.getsockname()[1]
        return port
    
    def _run_oauth_flow_with_popup(self, flow: InstalledAppFlow) -> Credentials:
        """Run OAuth flow with a popup window."""
        # Find a free port
        port = self._find_free_port()
        redirect_uri = f'http://localhost:{port}'
        
        # Set up the flow with our custom redirect URI
        flow.redirect_uri = redirect_uri
        
        # Get authorization URL
        auth_url, _ = flow.authorization_url(prompt='consent')
        
        logger.info(f"Opening browser for authentication...")
        print(f"\n🔐 Please authenticate with Google in your browser...")
        print(f"If the browser doesn't open automatically, visit: {auth_url}\n")
        
        # Open browser
        try:
            webbrowser.open(auth_url)
        except Exception as e:
            logger.warning(f"Could not open browser automatically: {e}")
            print(f"Please manually open this URL: {auth_url}")
        
        # Start callback server
        server = HTTPServer(('localhost', port), OAuthCallbackHandler)
        server.timeout = 300  # 5 minute timeout
        server.auth_code = None
        server.auth_error = None
        
        print(f"🌐 Waiting for authentication on http://localhost:{port}")
        print("✨ A browser window should have opened for you to sign in...")
        
        # Handle one request (the callback)
        try:
            server.handle_request()
        except Exception as e:
            logger.error(f"OAuth server error: {e}")
            raise Exception("Authentication server error")
        finally:
            server.server_close()
        
        # Check results
        if hasattr(server, 'auth_error') and server.auth_error:
            raise Exception(f"OAuth error: {server.auth_error}")
        
        if not hasattr(server, 'auth_code') or not server.auth_code:
            raise Exception("No authorization code received")
        
        # Exchange code for token
        try:
            flow.fetch_token(code=server.auth_code)
            logger.info("✅ Authentication successful!")
            print("✅ Authentication completed successfully!")
            return flow.credentials
        except Exception as e:
            logger.error(f"Token exchange failed: {e}")
            raise Exception(f"Failed to exchange authorization code: {e}")
    
    def authenticate_service(self, service_name: str, version: str, scopes: List[str]):
        """Authenticate and return Google service with popup login."""
        if not self._check_rate_limit(service_name):
            raise Exception("Rate limit exceeded")
        
        creds = self.credential_manager.load_credentials(service_name, scopes)
        credentials_path = self.credential_manager.script_dir / 'credentials.json'
        
        # Validate credentials file permissions
        if credentials_path.exists():
            stat = credentials_path.stat()
            if stat.st_mode & 0o077:
                logger.warning("Credentials file has overly permissive permissions")
        
        if not creds or not creds.valid:
            if creds and creds.expired and creds.refresh_token:
                try:
                    logger.info("Refreshing existing credentials...")
                    creds.refresh(Request())
                    logger.info("✅ Credentials refreshed successfully!")
                except Exception as e:
                    logger.error(f"Failed to refresh token: {e}")
                    creds = None
            
            if not creds:
                if not credentials_path.exists():
                    raise FileNotFoundError(
                        "credentials.json not found. Please download it from Google Cloud Console."
                    )
                
                logger.info(f"Starting new authentication flow for {service_name}...")
                flow = InstalledAppFlow.from_client_secrets_file(str(credentials_path), scopes)
                
                try:
                    # Use our custom popup flow
                    creds = self._run_oauth_flow_with_popup(flow)
                except Exception as e:
                    logger.error(f"Popup OAuth failed: {e}")
                    logger.info("Falling back to console OAuth...")
                    try:
                        creds = flow.run_console()
                    except Exception as console_error:
                        logger.error(f"Console OAuth also failed: {console_error}")
                        raise Exception(
                            "Both popup and console OAuth failed. "
                            "Please check your internet connection and credentials.json file."
                        )
            
            # Save the new credentials
            self.credential_manager.save_credentials(creds, service_name)
        
        return build(service_name, version, credentials=creds)

# Initialize secure services
secure_service = SecureGoogleService()

def get_tavily_client() -> TavilyClient:
    """Get Tavily client with API key from environment."""
    api_key = TAVILY_API_KEY or os.environ.get('TAVILY_API_KEY')
    if not api_key:
        raise ValueError("TAVILY_API_KEY environment variable not set")
    return TavilyClient(api_key=api_key)

def send_email(to: str, subject: str, body: str) -> Dict[str, Any]:
    """Send an email with security validation."""
    try:
        # Input validation
        if not InputValidator.validate_email_address(to):
            return {"error": "Invalid email address format"}
        
        subject = InputValidator.sanitize_string(subject, 200)
        body = InputValidator.sanitize_string(body, 50000)
        
        if len(body.encode('utf-8')) > SECURITY.MAX_EMAIL_SIZE:
            return {"error": "Email body too large"}
        
        service = secure_service.authenticate_service('gmail', 'v1', GMAIL_SCOPES)
        
        # Create properly formatted email
        email_content = f"To: {to}\r\nSubject: {subject}\r\n\r\n{body}"
        raw_message = base64.urlsafe_b64encode(email_content.encode('utf-8')).decode('utf-8')
        
        message = {'raw': raw_message}
        sent_message = service.users().messages().send(userId='me', body=message).execute()
        
        logger.info(f"Email sent successfully to {to[:10]}...")
        return {
            "success": True, 
            "message_id": sent_message['id'], 
            "message": "Email sent successfully!"
        }
        
    except Exception as e:
        logger.error(f"Failed to send email: {e}")
        return {"error": f"Failed to send email: {str(e)[:100]}"}

def add_label(message_id: str, label_name: str) -> Dict[str, Any]:
    """Add a label to an email with validation."""
    try:
        # Input validation
        message_id = InputValidator.sanitize_string(message_id, 50)
        label_name = InputValidator.sanitize_string(label_name, 100)
        
        if not message_id or not label_name:
            return {"error": "Invalid message ID or label name"}
        
        service = secure_service.authenticate_service('gmail', 'v1', GMAIL_SCOPES)
        
        # Get existing labels
        labels_response = service.users().labels().list(userId='me').execute()
        labels = labels_response.get('labels', [])
        
        label_id = None
        for label in labels:
            if label['name'].lower() == label_name.lower():
                label_id = label['id']
                break
        
        # Create label if it doesn't exist
        if not label_id:
            label_body = {
                'name': label_name, 
                'labelListVisibility': 'labelShow', 
                'messageListVisibility': 'messageShow'
            }
            created_label = service.users().labels().create(userId='me', body=label_body).execute()
            label_id = created_label['id']
        
        # Add label to message
        modify_request = {'addLabelIds': [label_id], 'removeLabelIds': []}
        service.users().messages().modify(userId='me', id=message_id, body=modify_request).execute()
        
        logger.info(f"Label '{label_name}' added to message {message_id}")
        return {"success": True, "message": f"Label '{label_name}' added to message."}
        
    except Exception as e:
        logger.error(f"Failed to add label: {e}")
        return {"error": f"Failed to add label: {str(e)[:100]}"}

def read_emails(query: str = "", max_results: int = 10) -> Dict[str, Any]:
    """Read emails with security validation."""
    try:
        # Input validation
        clean_query, safe_max_results = InputValidator.validate_query_params(query, max_results)
        
        service = secure_service.authenticate_service('gmail', 'v1', GMAIL_SCOPES)
        
        results = service.users().messages().list(
            userId='me', 
            q=clean_query if clean_query else None, 
            maxResults=safe_max_results
        ).execute()
        
        messages = results.get('messages', [])
        if not messages:
            return {"message": "No emails found."}
        
        email_list = []
        for message in messages[:safe_max_results]:  # Extra safety check
            try:
                msg = service.users().messages().get(
                    userId='me', 
                    id=message['id'], 
                    format='full'
                ).execute()
                
                headers = msg['payload'].get('headers', [])
                subject = next((h['value'] for h in headers if h['name'] == 'Subject'), 'No Subject')
                sender = next((h['value'] for h in headers if h['name'] == 'From'), 'Unknown Sender')
                
                # Sanitize header values
                subject = InputValidator.sanitize_string(subject, 500)
                sender = InputValidator.sanitize_string(sender, 500)
                
                # Extract body safely
                body = extract_email_body(msg['payload'])
                body = InputValidator.sanitize_string(body, 10000)  # Limit body size
                
                email_list.append({
                    "id": message['id'],
                    "subject": subject,
                    "from": sender,
                    "snippet": InputValidator.sanitize_string(msg.get('snippet', ''), 500),
                    "body": body
                })
                
            except Exception as e:
                logger.error(f"Failed to process message {message['id']}: {e}")
                continue
        
        logger.info(f"Read {len(email_list)} emails")
        return {"success": True, "emails": email_list, "count": len(email_list)}
        
    except Exception as e:
        logger.error(f"Failed to read emails: {e}")
        return {"error": f"Failed to read emails: {str(e)[:100]}"}

def extract_email_body(payload: Dict) -> str:
    """Safely extract email body from payload."""
    try:
        if 'parts' in payload:
            for part in payload['parts']:
                if part.get('mimeType') == 'text/plain' and 'data' in part.get('body', {}):
                    return base64.urlsafe_b64decode(part['body']['data']).decode('utf-8', errors='ignore')
        elif 'data' in payload.get('body', {}):
            return base64.urlsafe_b64decode(payload['body']['data']).decode('utf-8', errors='ignore')
    except Exception as e:
        logger.error(f"Failed to extract email body: {e}")
    
    return ""

def web_search(query: str) -> Dict[str, Any]:
    """Search the web with input validation."""
    try:
        clean_query = InputValidator.sanitize_string(query, 500)
        if not clean_query:
            return {"error": "Invalid search query"}
        
        tavily = get_tavily_client()
        result = tavily.search(
            query=clean_query,
            search_depth="advanced",
            max_results=min(5, SECURITY.MAX_SEARCH_RESULTS),  # Limit results
            include_images=False,  # Disable for security
            include_image_descriptions=False,
            include_raw_content=False  # Disable raw content for security
        )
        
        logger.info(f"Web search completed for query: {clean_query[:50]}...")
        return result
        
    except Exception as e:
        logger.error(f"Web search failed: {e}")
        return {"error": f"Web search failed: {str(e)[:100]}"}

def parse_datetime(date_str: str, time_str: str = None) -> str:
    """Parse date and time strings with validation."""
    try:
        # Input validation
        date_str = InputValidator.sanitize_string(date_str, 50)
        if time_str:
            time_str = InputValidator.sanitize_string(time_str, 20)
        
        # Handle various date formats
        date_formats = [
            '%Y-%m-%d', '%m/%d/%Y', '%d/%m/%Y', 
            '%B %d, %Y', '%b %d, %Y', '%Y-%m-%d %H:%M:%S'
        ]
        date_obj = None
        
        for fmt in date_formats:
            try:
                date_obj = datetime.strptime(date_str, fmt)
                break
            except ValueError:
                continue
        
        if not date_obj:
            try:
                from dateutil.parser import parse
                date_obj = parse(date_str, fuzzy=False)
            except Exception:
                raise ValueError(f"Could not parse date: {date_str}")
        
        if time_str:
            time_formats = ['%H:%M', '%I:%M %p', '%H:%M:%S']
            time_obj = None
            
            for fmt in time_formats:
                try:
                    time_obj = datetime.strptime(time_str, fmt).time()
                    break
                except ValueError:
                    continue
            
            if time_obj:
                date_obj = datetime.combine(date_obj.date(), time_obj)
        
        # Validate date is not too far in the past or future
        now = datetime.now()
        min_date = now - timedelta(days=3650)  # 10 years ago
        max_date = now + timedelta(days=3650)   # 10 years from now
        
        if not (min_date <= date_obj <= max_date):
            raise ValueError("Date is outside acceptable range")
        
        return date_obj.isoformat()
        
    except Exception as e:
        logger.error(f"Date parsing failed: {e}")
        raise ValueError(f"Could not parse date/time: {str(e)[:100]}")

def create_calendar_event(title: str, start_date: str, end_date: str = None, 
                         start_time: str = None, end_time: str = None, 
                         description: str = "", location: str = "") -> Dict[str, Any]:
    """Create a calendar event with validation."""
    try:
        # Input validation
        title = InputValidator.sanitize_string(title, 255)
        description = InputValidator.sanitize_string(description, 8192)
        location = InputValidator.sanitize_string(location, 255)
        
        if not title:
            return {"error": "Event title is required"}
        
        service = secure_service.authenticate_service('calendar', 'v3', CALENDAR_SCOPES)
        
        # Parse datetimes
        start_datetime = parse_datetime(start_date, start_time)
        
        if end_date and end_time:
            end_datetime = parse_datetime(end_date, end_time)
        elif end_time:
            end_datetime = parse_datetime(start_date, end_time)
        elif end_date:
            end_datetime = parse_datetime(end_date)
        else:
            # Default to 1 hour duration
            start_dt = datetime.fromisoformat(start_datetime)
            end_dt = start_dt + timedelta(hours=1)
            end_datetime = end_dt.isoformat()
        
        # Validate end is after start
        if datetime.fromisoformat(end_datetime) <= datetime.fromisoformat(start_datetime):
            return {"error": "End time must be after start time"}
        
        event = {
            'summary': title,
            'location': location,
            'description': description,
            'start': {
                'dateTime': start_datetime,
                'timeZone': 'UTC',  # Use UTC for consistency
            },
            'end': {
                'dateTime': end_datetime,
                'timeZone': 'UTC',
            },
        }
        
        event_result = service.events().insert(calendarId='primary', body=event).execute()
        
        logger.info(f"Calendar event created: {title}")
        return {
            "success": True,
            "event_id": event_result.get('id'),
            "event_link": event_result.get('htmlLink'),
            "message": f"Event '{title}' created successfully!"
        }
        
    except Exception as e:
        logger.error(f"Failed to create calendar event: {e}")
        return {"error": f"Failed to create event: {str(e)[:100]}"}

def search_calendar_events(query: str = "", start_date: str = "", end_date: str = "", 
                          max_results: int = 10) -> Dict[str, Any]:
    """Search calendar events with validation."""
    try:
        # Input validation
        clean_query, safe_max_results = InputValidator.validate_query_params(query, max_results)
        safe_max_results = min(safe_max_results, SECURITY.MAX_CALENDAR_RESULTS)
        
        service = secure_service.authenticate_service('calendar', 'v3', CALENDAR_SCOPES)
        
        # Set default time range
        if not start_date:
            start_time_min = datetime.now().isoformat() + 'Z'
        else:
            start_time_min = parse_datetime(start_date) + 'Z'
        
        if not end_date:
            end_time = datetime.now() + timedelta(days=30)
            end_time_max = end_time.isoformat() + 'Z'
        else:
            end_time_max = parse_datetime(end_date) + 'Z'
        
        events_result = service.events().list(
            calendarId='primary',
            timeMin=start_time_min,
            timeMax=end_time_max,
            maxResults=safe_max_results,
            singleEvents=True,
            orderBy='startTime',
            q=clean_query if clean_query else None
        ).execute()
        
        events = events_result.get('items', [])
        
        if not events:
            return {"message": "No events found."}
        
        event_list = []
        for event in events:
            start = event['start'].get('dateTime', event['start'].get('date'))
            end = event['end'].get('dateTime', event['end'].get('date'))
            
            event_info = {
                "id": event['id'],
                "title": InputValidator.sanitize_string(event.get('summary', 'No title'), 255),
                "start": start,
                "end": end,
                "description": InputValidator.sanitize_string(event.get('description', ''), 1000),
                "location": InputValidator.sanitize_string(event.get('location', ''), 255),
                "link": event.get('htmlLink', '')
            }
            event_list.append(event_info)
        
        logger.info(f"Found {len(event_list)} calendar events")
        return {"success": True, "events": event_list, "count": len(event_list)}
        
    except Exception as e:
        logger.error(f"Failed to search calendar events: {e}")
        return {"error": f"Failed to search events: {str(e)[:100]}"}

def update_calendar_event(event_id: str, title: str = None, start_date: str = None, 
                         end_date: str = None, start_time: str = None, end_time: str = None,
                         description: str = None, location: str = None) -> Dict[str, Any]:
    """Update a calendar event with validation."""
    try:
        # Input validation
        event_id = InputValidator.sanitize_string(event_id, 100)
        if not event_id:
            return {"error": "Invalid event ID"}
        
        service = secure_service.authenticate_service('calendar', 'v3', CALENDAR_SCOPES)
        
        # Get existing event
        event = service.events().get(calendarId='primary', eventId=event_id).execute()
        
        # Update fields with validation
        if title is not None:
            title = InputValidator.sanitize_string(title, 255)
            if title:  # Only update if not empty
                event['summary'] = title
        
        if description is not None:
            event['description'] = InputValidator.sanitize_string(description, 8192)
        
        if location is not None:
            event['location'] = InputValidator.sanitize_string(location, 255)
        
        # Update datetimes
        if start_date or start_time:
            current_start = event['start'].get('dateTime', event['start'].get('date'))
            if start_date and start_time:
                new_start = parse_datetime(start_date, start_time)
            elif start_date:
                new_start = parse_datetime(start_date)
            elif start_time:
                existing_date = current_start.split('T')[0]
                new_start = parse_datetime(existing_date, start_time)
            
            event['start']['dateTime'] = new_start
            event['start']['timeZone'] = 'UTC'
        
        if end_date or end_time:
            current_end = event['end'].get('dateTime', event['end'].get('date'))
            if end_date and end_time:
                new_end = parse_datetime(end_date, end_time)
            elif end_date:
                new_end = parse_datetime(end_date)
            elif end_time:
                existing_date = current_end.split('T')[0]
                new_end = parse_datetime(existing_date, end_time)
            
            event['end']['dateTime'] = new_end
            event['end']['timeZone'] = 'UTC'
        
        # Validate end is after start if both are present
        if 'dateTime' in event['start'] and 'dateTime' in event['end']:
            start_dt = datetime.fromisoformat(event['start']['dateTime'])
            end_dt = datetime.fromisoformat(event['end']['dateTime'])
            if end_dt <= start_dt:
                return {"error": "End time must be after start time"}
        
        updated_event = service.events().update(
            calendarId='primary', 
            eventId=event_id, 
            body=event
        ).execute()
        
        logger.info(f"Calendar event updated: {event_id}")
        return {
            "success": True,
            "event_id": updated_event.get('id'),
            "message": "Event updated successfully!"
        }
        
    except Exception as e:
        logger.error(f"Failed to update calendar event: {e}")
        return {"error": f"Failed to update event: {str(e)[:100]}"}

def delete_calendar_event(event_id: str) -> Dict[str, Any]:
    """Delete a calendar event with validation."""
    try:
        # Input validation
        event_id = InputValidator.sanitize_string(event_id, 100)
        if not event_id:
            return {"error": "Invalid event ID"}
        
        service = secure_service.authenticate_service('calendar', 'v3', CALENDAR_SCOPES)
        
        # Verify event exists before deletion
        try:
            service.events().get(calendarId='primary', eventId=event_id).execute()
        except HttpError as e:
            if e.resp.status == 404:
                return {"error": "Event not found"}
            raise
        
        service.events().delete(calendarId='primary', eventId=event_id).execute()
        
        logger.info(f"Calendar event deleted: {event_id}")
        return {"success": True, "message": "Event deleted successfully!"}
        
    except Exception as e:
        logger.error(f"Failed to delete calendar event: {e}")
        return {"error": f"Failed to delete event: {str(e)[:100]}"}
