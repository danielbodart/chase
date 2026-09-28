from google.cloud import storage
import google.auth
creds, proj = google.auth.default()
print("adc:", type(creds).__module__, type(creds).__name__, "project:", proj)
b = storage.Client().bucket("danbodart-sandbox-test-frisket-spike")
print("python storage download:", repr(b.blob("hello.txt").download_as_bytes()))
