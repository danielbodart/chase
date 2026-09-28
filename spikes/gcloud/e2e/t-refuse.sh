SA=frisket-spike@danbodart-sandbox-test.iam.gserviceaccount.com
H='Authorization: Bearer proxy-injected'
r(){ echo "### $1"; shift; curl -sS -m 8 -o /tmp/body -w 'http=%{http_code}\n' "$@" 2>&1; head -c 220 /tmp/body 2>/dev/null | tr '\n' ' '; echo; }
r "iamcredentials generateAccessToken" -X POST -H "$H" -H 'Content-Type: application/json' -d '{"scope":["https://www.googleapis.com/auth/cloud-platform"]}' https://iamcredentials.googleapis.com/v1/projects/-/serviceAccounts/$SA:generateAccessToken
r "iamcredentials signJwt" -X POST -H "$H" -d '{"payload":"{}"}' https://iamcredentials.googleapis.com/v1/projects/-/serviceAccounts/$SA:signJwt
r "sts token" -X POST -d 'grant_type=urn:ietf:params:oauth:grant-type:token-exchange' https://sts.googleapis.com/v1/token
r "oauth2 token" -X POST -d 'grant_type=refresh_token&refresh_token=proxy-injected' https://oauth2.googleapis.com/token
r "oauth2 tokeninfo" -H "$H" https://oauth2.googleapis.com/tokeninfo
echo "=== alternates under the wildcard"
r "www.googleapis.com oauth2/v4/token" -X POST -d 'grant_type=refresh_token&refresh_token=proxy-injected&client_id=x' https://www.googleapis.com/oauth2/v4/token
r "www.googleapis.com oauth2/v3/tokeninfo (header)" -H "$H" https://www.googleapis.com/oauth2/v3/tokeninfo
r "www.googleapis.com oauth2/v1/tokeninfo (header)" -H "$H" https://www.googleapis.com/oauth2/v1/tokeninfo
r "iam.googleapis.com keys.create" -X POST -H "$H" -H 'Content-Type: application/json' -d '{}' https://iam.googleapis.com/v1/projects/-/serviceAccounts/$SA/keys
r "iam.googleapis.com v1 signJwt" -X POST -H "$H" -H 'Content-Type: application/json' -d '{"payload":"{}"}' https://iam.googleapis.com/v1/projects/-/serviceAccounts/$SA:signJwt
r "iamcredentials.mtls" -X POST -H "$H" -d '{}' https://iamcredentials.mtls.googleapis.com/v1/projects/-/serviceAccounts/$SA:generateAccessToken
r "iamcredentials regional rep" -X POST -H "$H" -d '{}' https://iamcredentials.us-central1.rep.googleapis.com/v1/projects/-/serviceAccounts/$SA:generateAccessToken
r "sts.mtls" -X POST -d 'grant_type=x' https://sts.mtls.googleapis.com/v1/token
echo "=== bypass attempts"
r "direct IP 142.250.180.27 (storage) w/ --resolve" --resolve storage.googleapis.com:443:142.250.180.27 -H "$H" https://storage.googleapis.com/storage/v1/b/danbodart-sandbox-test-frisket-spike/o
r "169.254.169.254 metadata" -H 'Metadata-Flavor: Google' http://169.254.169.254/computeMetadata/v1/instance/service-accounts/default/token
r "metadata.google.internal" -H 'Metadata-Flavor: Google' http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token
r "accounts.google.com" https://accounts.google.com/
r "googleapis.com apex" https://googleapis.com/
r "metadata w/o flavor" http://192.0.2.2/computeMetadata/v1/instance/service-accounts/default/token
r "metadata identity" -H 'Metadata-Flavor: Google' 'http://192.0.2.2/computeMetadata/v1/instance/service-accounts/default/identity?audience=x'
r "metadata via XFF" -H 'Metadata-Flavor: Google' -H 'X-Forwarded-For: 1.2.3.4' http://192.0.2.2/computeMetadata/v1/instance/service-accounts/default/token
r "storage with no CA (-k absent, system bundle)" --cacert /etc/ssl/certs/ca-certificates.crt https://storage.googleapis.com/
echo "### UDP/QUIC to 8.8.8.8:443"; timeout 3 bash -c 'echo x > /dev/udp/8.8.8.8/443' ; echo "rc=$?"
echo "### DNS via 8.8.8.8 for accounts.google.com"; python3 -c '
import socket
try: print(socket.getaddrinfo("accounts.google.com",443)[0][4])
except Exception as e: print("resolve:", e)'
