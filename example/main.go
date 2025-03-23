package main

import (
	"context"
	"encoding/json"
	"log"

	"github.com/chrispassas/whois"
)

func main() {
	wl := whois.Setup(whois.DefaultConfig())

	info, raw, err := wl.GetRegistrarWhois(context.Background(), "github.com")
	if err != nil {
		log.Printf("error: %v", err)
	} else {
		var jsonBytes []byte
		if jsonBytes, err = json.MarshalIndent(info, "", "  "); err != nil {
			log.Printf("error: %v", err)
		}
		log.Printf("json: %v", string(jsonBytes))
		log.Printf("raw: %v", raw)
	}

}
