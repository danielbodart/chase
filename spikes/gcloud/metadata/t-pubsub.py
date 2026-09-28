import os, time
from google.cloud import pubsub_v1
t0 = time.time()
pub = pubsub_v1.PublisherClient()
for i in range(int(os.environ.get("LOOPS", "2"))):
    topics = list(pub.list_topics(request={"project": "projects/frisket-spike"}))
    print(i, "list_topics ok:", topics, f"{time.time()-t0:.2f}s")
    time.sleep(float(os.environ.get("SLEEP", "1")))
