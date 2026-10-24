"""Print fresh secrets for the server. Store them in your environment / secret
manager, never in git."""
import base64
import secrets

print("PWVAULT_JWT_SECRET=" + secrets.token_urlsafe(48))
print("PWVAULT_SERVER_KEY=" + base64.b64encode(secrets.token_bytes(32)).decode())
