package main

import (
	"log"

	"github.com/zero-day-ai/sdk/serve"
	"github.com/zero-day-ai/gibson-tool-nuclei"
)

func main() {
	tool := nuclei.NewTool()
	if err := serve.Tool(tool,
		serve.WithRegistryFromEnv(),
	); err != nil {
		log.Fatal(err)
	}
}
