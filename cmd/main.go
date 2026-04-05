package main

import (
	"log"
	"time"

	"github.com/zero-day-ai/sdk/serve"
	"github.com/zero-day-ai/gibson-tool-nuclei"
)

func main() {
	tool := nuclei.NewTool()
	if err := serve.Tool(tool,
		serve.WithPlatformFromEnv(),
		serve.WithGracefulShutdown(30*time.Second),
		serve.WithExtractor(nuclei.NewNucleiExtractor()),
	); err != nil {
		log.Fatal(err)
	}
}
