import sys
from google.cloud import pubsub_v1, resourcemanager_v3
T = "projects/danbodart-sandbox-test/topics/frisket-spike"
for tr in ("grpc", "rest"):
    try:
        p = pubsub_v1.PublisherClient(transport=tr)
        print(f"pubsub {tr} get_topic:", p.get_topic(request={"topic": T}).name)
        print(f"pubsub {tr} get_topic again:", p.get_topic(request={"topic": T}).name)
    except Exception as e:
        print(f"pubsub {tr} FAIL", type(e).__name__, str(e)[:200])
for tr in ("grpc", "rest"):
    try:
        c = resourcemanager_v3.ProjectsClient(transport=tr)
        print(f"crm {tr}:", c.get_project(name="projects/danbodart-sandbox-test").project_id)
    except Exception as e:
        print(f"crm {tr}:", type(e).__name__, str(e)[:200])
