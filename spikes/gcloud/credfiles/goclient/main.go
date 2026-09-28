package main

import (
	"context"
	"fmt"
	"io"
	"os"
	"strconv"
	"time"

	"golang.org/x/oauth2/google"
	"google.golang.org/api/option"
	"google.golang.org/api/option/internaloption"
	storage "google.golang.org/api/storage/v1"
)

func main() {
	ctx := context.Background()
	mode := os.Args[1]
	n, _ := strconv.Atoi(os.Getenv("N"))
	if n == 0 {
		n = 2
	}
	sleep, _ := time.ParseDuration(os.Getenv("SLEEP") + "s")
	scope := "https://www.googleapis.com/auth/cloud-platform"
	switch mode {
	case "oauth2":
		creds, err := google.FindDefaultCredentials(ctx, scope)
		if err != nil {
			fmt.Println("find:", err)
			os.Exit(1)
		}
		for i := 0; i < n; i++ {
			tok, err := creds.TokenSource.Token()
			if err != nil {
				fmt.Println("token:", err)
				os.Exit(1)
			}
			fmt.Println("token:", tok.AccessToken, "expiry:", tok.Expiry.Format(time.RFC3339), "id_token:", tok.Extra("id_token") != nil)
			time.Sleep(sleep)
		}
	case "api", "api-noscope", "api-gapic":
		opts := []option.ClientOption{}
		if mode == "api-gapic" {
			opts = append(opts, option.WithScopes(scope), internaloption.EnableJwtWithScope(), internaloption.WithDefaultAudience("https://storage.googleapis.com/"))
		}
		if mode == "api" {
			opts = append(opts, option.WithScopes(scope))
		}
		svc, err := storage.NewService(ctx, opts...)
		if err != nil {
			fmt.Println("svc:", err)
			os.Exit(1)
		}
		for i := 0; i < n; i++ {
			r, err := svc.Buckets.List("spike-proj").Do()
			if err != nil {
				fmt.Println("list:", err)
				os.Exit(1)
			}
			fmt.Println("buckets:", len(r.Items))
			time.Sleep(sleep)
		}
	}
	_ = io.EOF
}
