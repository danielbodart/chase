package main

import (
	"context"
	"fmt"
	"io"
	"os"

	"cloud.google.com/go/storage"
)

func main() {
	ctx := context.Background()
	c, err := storage.NewClient(ctx)
	if err != nil {
		fmt.Println("go FAIL client", err)
		os.Exit(1)
	}
	for _, grpc := range []bool{false, true} {
		if grpc {
			c, err = storage.NewGRPCClient(ctx)
			if err != nil {
				fmt.Println("go FAIL grpc client", err)
				os.Exit(1)
			}
		}
		r, err := c.Bucket("danbodart-sandbox-test-frisket-spike").Object("hello.txt").NewReader(ctx)
		if err != nil {
			fmt.Println("go FAIL grpc=", grpc, err)
			continue
		}
		b, _ := io.ReadAll(r)
		fmt.Printf("go download grpc=%v: %q\n", grpc, b)
	}
}
