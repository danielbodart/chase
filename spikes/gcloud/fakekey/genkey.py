import json, os, secrets, sys
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
F, email, project = sys.argv[1], sys.argv[2], sys.argv[3]
k = rsa.generate_private_key(public_exponent=65537, key_size=2048)
priv = k.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()).decode()
pub = k.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
open(f"{F}/host/fake-pub.pem", "wb").write(pub)
doc = {"type": "service_account", "project_id": project, "private_key_id": secrets.token_hex(20),
       "private_key": priv, "client_email": email, "client_id": "000000000000000000000",
       "auth_uri": "https://accounts.google.com/o/oauth2/auth", "token_uri": "https://oauth2.googleapis.com/token",
       "auth_provider_x509_cert_url": "https://www.googleapis.com/oauth2/v1/certs",
       "client_x509_cert_url": "https://www.googleapis.com/robot/v1/metadata/x509/" + email.replace("@", "%40"),
       "universe_domain": "googleapis.com"}
json.dump(doc, open(f"{F}/sbx/home/fake-key.json", "w"), indent=1)
print("fake key kid", doc["private_key_id"][:8], "…")
