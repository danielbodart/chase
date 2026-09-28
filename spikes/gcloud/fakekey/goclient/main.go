package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"strings"

	pubsub "cloud.google.com/go/pubsub/apiv1"
	"cloud.google.com/go/pubsub/apiv1/pubsubpb"
	"cloud.google.com/go/storage"
	"google.golang.org/api/idtoken"
)

const topic = "projects/danbodart-sandbox-test/topics/frisket-spike"

func main() {
	ctx := context.Background()
	for _, grpc := range []bool{false, true} {
		var c *storage.Client
		var err error
		if grpc {
			c, err = storage.NewGRPCClient(ctx)
		} else {
			c, err = storage.NewClient(ctx)
		}
		if err != nil {
			fmt.Println("go storage client FAIL", grpc, err)
			continue
		}
		r, err := c.Bucket("danbodart-sandbox-test-frisket-spike").Object("hello.txt").NewReader(ctx)
		if err != nil {
			fmt.Printf("go storage grpc=%v FAIL %v\n", grpc, err)
			continue
		}
		b, _ := io.ReadAll(r)
		fmt.Printf("go storage grpc=%v: %q\n", grpc, b)
	}
	pg, err := pubsub.NewPublisherClient(ctx)
	if err == nil {
		for i := 0; i < 2; i++ {
			t, err := pg.GetTopic(ctx, &pubsubpb.GetTopicRequest{Topic: topic})
			fmt.Println("go pubsub gapic grpc GetTopic:", name(t), err)
		}
	}
	pr, err := pubsub.NewPublisherRESTClient(ctx)
	if err == nil {
		for i := 0; i < 2; i++ {
			t, err := pr.GetTopic(ctx, &pubsubpb.GetTopicRequest{Topic: topic})
			fmt.Println("go pubsub gapic rest GetTopic:", name(t), err)
		}
	}
	ts, err := idtoken.NewTokenSource(ctx, "https://example-run-service.a.run.app")
	if err != nil {
		fmt.Println("go idtoken FAIL", err)
		return
	}
	tok, err := ts.Token()
	if err != nil {
		fmt.Println("go idtoken FAIL", err)
		return
	}
	p := strings.Split(tok.AccessToken, ".")
	cb, _ := base64.RawURLEncoding.DecodeString(p[1])
	var m map[string]any
	json.Unmarshal(cb, &m)
	fmt.Println("go idtoken ok: iss", m["iss"], "aud", m["aud"], "expiry", tok.Expiry)
}

func name(t *pubsubpb.Topic) string {
	if t == nil {
		return ""
	}
	return t.Name
}
