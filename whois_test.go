package whois

import (
	"context"
	"testing"
	"time"
)

func TestDefaultConfig(t *testing.T) {
	config := DefaultConfig()

	if config.RootCacheDuration != 1*time.Hour {
		t.Errorf("expected RootCacheDuration to be 1 hour, got %v", config.RootCacheDuration)
	}

	if config.DefaultTimeout != 15*time.Second {
		t.Errorf("expected DefaultTimeout to be 15 seconds, got %v", config.DefaultTimeout)
	}

	if config.WhoisTLDServer != "whois.iana.org:43" {
		t.Errorf("expected WhoisTLDServer to be 'whois.iana.org:43', got %v", config.WhoisTLDServer)
	}
}

func TestSetup(t *testing.T) {
	config := &Config{
		RootCacheDuration: 2 * time.Hour,
		DefaultTimeout:    30 * time.Second,
		WhoisTLDServer:    "custom.whois.server:43",
	}

	whoisLookup := Setup(config)

	if whoisLookup.config.RootCacheDuration != 2*time.Hour {
		t.Errorf("expected RootCacheDuration to be 2 hours, got %v", whoisLookup.config.RootCacheDuration)
	}

	if whoisLookup.config.DefaultTimeout != 30*time.Second {
		t.Errorf("expected DefaultTimeout to be 30 seconds, got %v", whoisLookup.config.DefaultTimeout)
	}

	if whoisLookup.config.WhoisTLDServer != "custom.whois.server:43" {
		t.Errorf("expected WhoisTLDServer to be 'custom.whois.server:43', got %v", whoisLookup.config.WhoisTLDServer)
	}
}

func TestGetTLDWhoisServer(t *testing.T) {
	whoisLookup := Setup(nil)
	ctx := context.Background()

	// Mock TLD server
	whoisLookup.setTLDServerToCache("com", "whois.verisign-grs.com")

	server, err := whoisLookup.GetTLDWhoisServer(ctx, "com")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if server != "whois.verisign-grs.com" {
		t.Errorf("expected server to be 'whois.verisign-grs.com', got %v", server)
	}
}

func TestGetRegistryWhois_InvalidDomain(t *testing.T) {
	whoisLookup := Setup(nil)
	ctx := context.Background()

	_, _, err := whoisLookup.GetRegistryWhois(ctx, "invalid_domain")
	if err == nil {
		t.Fatal("expected an error for invalid domain, got nil")
	}
}

func TestGetRegistrarWhois_InvalidDomain(t *testing.T) {
	whoisLookup := Setup(nil)
	ctx := context.Background()

	_, _, err := whoisLookup.GetRegistrarWhois(ctx, "invalid_domain")
	if err == nil {
		t.Fatal("expected an error for invalid domain, got nil")
	}
}

func TestSetAndGetTLDServerFromCache(t *testing.T) {
	whoisLookup := Setup(nil)

	tld := "org"
	server := "whois.pir.org"

	whoisLookup.setTLDServerToCache(tld, server)

	cachedServer := whoisLookup.getTLDServerFromCache(tld)
	if cachedServer != server {
		t.Errorf("expected cached server to be %v, got %v", server, cachedServer)
	}
}
