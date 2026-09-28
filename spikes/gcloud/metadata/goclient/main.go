package main

import (
	"context"
	"fmt"
	"io"
	"os"
	"strconv"
	"time"

	"cloud.google.com/go/compute/metadata"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
)

func main() {
	ctx := context.Background()
	t0 := time.Now()
	fmt.Println("metadata.OnGCE:", metadata.OnGCE(), time.Since(t0))
	pid, err := metadata.ProjectIDWithContext(ctx)
	fmt.Println("metadata.ProjectID:", pid, err)
	t1 := time.Now()
	creds, err := google.FindDefaultCredentials(ctx, "https://www.googleapis.com/auth/cloud-platform")
	if err != nil {
		fmt.Println("FindDefaultCredentials error:", err)
		os.Exit(1)
	}
	fmt.Println("FindDefaultCredentials ok, ProjectID:", creds.ProjectID, time.Since(t1))
	client := oauth2.NewClient(ctx, creds.TokenSource)
	n, _ := strconv.Atoi(os.Getenv("LOOPS"))
	if n == 0 {
		n = 1
	}
	for i := 0; i < n; i++ {
		resp, err := client.Get("https://storage.googleapis.com/storage/v1/b?project=frisket-spike")
		if err != nil {
			fmt.Println("GET error:", err)
		} else {
			b, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			fmt.Println("GET", resp.Status, string(b))
		}
		if i+1 < n {
			time.Sleep(time.Second)
		}
	}
}
