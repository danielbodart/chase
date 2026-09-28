import sys
from google.cloud import storage, pubsub_v1
b = storage.Client().bucket("danbodart-sandbox-test-frisket-spike")
print("python download:", repr(b.blob("hello.txt").download_as_bytes()))
p = pubsub_v1.PublisherClient()
t = p.get_topic(request={"topic": "projects/danbodart-sandbox-test/topics/frisket-spike"})
print("python pubsub grpc get_topic:", t.name)
try:
    print("list_topics:", [x.name for x in p.list_topics(request={"project": "projects/danbodart-sandbox-test"})])
except Exception as e:
    print("list_topics:", type(e).__name__, str(e)[:160])
