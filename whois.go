package whois

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	whoisparser "github.com/likexian/whois-parser"
)

var (
	// ErrWhoisServerNotFound is returned when the WHOIS server for a TLD is not found.
	ErrWhoisServerNotFound = fmt.Errorf("WHOIS server not found for TLD")
)

type WhoisLookup struct {
	m                sync.RWMutex
	rootWhoisServers map[string]rootTLDCache
	config           Config
}

type rootTLDCache struct {
	Host        string
	LastUpdated time.Time
}

type Config struct {
	RootCacheDuration time.Duration `json:"root_cache_duration"`
	DefaultTimeout    time.Duration `json:"default_timeout"`
	WhoisTLDServer    string        `json:"whois_tld_server"`
}

type WhoisInfo struct {
	Domain         *Domain  `json:"domain,omitempty"`
	Registrar      *Contact `json:"registrar,omitempty"`
	Registrant     *Contact `json:"registrant,omitempty"`
	Administrative *Contact `json:"administrative,omitempty"`
	Technical      *Contact `json:"technical,omitempty"`
	Billing        *Contact `json:"billing,omitempty"`
}

type Domain struct {
	ID                   string     `json:"id,omitempty"`
	Domain               string     `json:"domain,omitempty"`
	Punycode             string     `json:"punycode,omitempty"`
	Name                 string     `json:"name,omitempty"`
	Extension            string     `json:"extension,omitempty"`
	WhoisServer          string     `json:"whois_server,omitempty"`
	Status               []string   `json:"status,omitempty"`
	NameServers          []string   `json:"name_servers,omitempty"`
	DNSSec               bool       `json:"dnssec,omitempty"`
	CreatedDate          string     `json:"created_date,omitempty"`
	CreatedDateInTime    *time.Time `json:"created_date_in_time,omitempty"`
	UpdatedDate          string     `json:"updated_date,omitempty"`
	UpdatedDateInTime    *time.Time `json:"updated_date_in_time,omitempty"`
	ExpirationDate       string     `json:"expiration_date,omitempty"`
	ExpirationDateInTime *time.Time `json:"expiration_date_in_time,omitempty"`
}

type Contact struct {
	ID           string `json:"id,omitempty"`
	Name         string `json:"name,omitempty"`
	Organization string `json:"organization,omitempty"`
	Street       string `json:"street,omitempty"`
	City         string `json:"city,omitempty"`
	Province     string `json:"province,omitempty"`
	PostalCode   string `json:"postal_code,omitempty"`
	Country      string `json:"country,omitempty"`
	Phone        string `json:"phone,omitempty"`
	PhoneExt     string `json:"phone_ext,omitempty"`
	Fax          string `json:"fax,omitempty"`
	FaxExt       string `json:"fax_ext,omitempty"`
	Email        string `json:"email,omitempty"`
	ReferralURL  string `json:"referral_url,omitempty"`
}

func DefaultConfig() *Config {
	return &Config{
		RootCacheDuration: 1 * time.Hour,
		DefaultTimeout:    15 * time.Second,
		WhoisTLDServer:    "whois.iana.org:43",
	}
}

func Setup(config *Config) (whoisLookup *WhoisLookup) {

	defaultConfig := DefaultConfig()
	if config == nil {
		config = defaultConfig
	} else {
		if config.RootCacheDuration == 0 {
			config.RootCacheDuration = defaultConfig.RootCacheDuration
		}
		if config.DefaultTimeout == 0 {
			config.DefaultTimeout = defaultConfig.DefaultTimeout
		}
		if config.WhoisTLDServer == "" {
			config.WhoisTLDServer = defaultConfig.WhoisTLDServer
		}
	}

	return &WhoisLookup{
		rootWhoisServers: make(map[string]rootTLDCache),
		config:           *config,
	}
}

// GetTLDWhoisServer returns the WHOIS server for the specified TLD.
func (wl *WhoisLookup) GetTLDWhoisServer(ctx context.Context, tld string) (tldServer string, err error) {

	if tldServer, err = wl.getWhoisServerForTLD(ctx, tld); err != nil {
		err = fmt.Errorf("wl.getTLDWhoisServer() error:%w", err)
		return tldServer, err
	}

	return tldServer, err
}

// GetWhois returns the WHOIS information for the specified domain.
func (wl *WhoisLookup) GetWhois(ctx context.Context, domain string) (whoisInfo WhoisInfo, whoisRaw string, err error) {

	pieces := strings.Split(domain, ".")
	if len(pieces) < 2 {
		err = fmt.Errorf("invalid domain name: %s", domain)
		return whoisInfo, whoisRaw, err
	}
	tld := pieces[len(pieces)-1]

	// Get TLD whois server
	var whoisServer string
	if whoisServer, err = wl.getWhoisServerForTLD(ctx, tld); err != nil {
		err = fmt.Errorf("getTLDWhoisServer() error:%w", err)
		return whoisInfo, whoisRaw, err
	}

	// Query TLD whois server
	if whoisRaw, err = queryWhois(ctx, domain, whoisServer, wl.config.DefaultTimeout); err != nil {
		err = fmt.Errorf("queryWhois() error:%w", err)
		return whoisInfo, whoisRaw, err
	}

	// Parse raw whois data to WhoisInfo
	if whoisInfo, err = wrapParser(whoisRaw); err != nil {
		err = fmt.Errorf("parse error:%w", err)
		return whoisInfo, whoisRaw, err
	}

	// If TLD whois responsec contains domain whois server, query domain whois server
	if whoisInfo.Domain.WhoisServer != "" {
		if whoisRaw, err = queryWhois(ctx, domain, whoisInfo.Domain.WhoisServer, wl.config.DefaultTimeout); err != nil {
			err = fmt.Errorf("queryWhois() error:%w", err)
			return whoisInfo, whoisRaw, err
		}
		if whoisInfo, err = wrapParser(whoisRaw); err != nil {
			err = fmt.Errorf("parse error:%w", err)
			return whoisInfo, whoisRaw, err
		}
	}

	return whoisInfo, whoisRaw, err
}

// queryWhois queries the specified WHOIS server for the specified domain.
func queryWhois(ctx context.Context, domain, whoisServer string, timeout time.Duration) (rawWhois string, err error) {

	var (
		dialer = net.Dialer{
			Timeout: timeout,
		}
		conn net.Conn
	)

	if conn, err = dialer.DialContext(ctx, "tcp", whoisServer+":43"); err != nil {
		err = fmt.Errorf("dialer.DialContext() error:%w", err)
		return rawWhois, err
	}
	defer conn.Close()

	// Send the domain query followed by a newline
	fmt.Fprintf(conn, "%s\r\n", domain)

	// Read the response from the server
	var response strings.Builder
	scanner := bufio.NewScanner(conn)
	for scanner.Scan() {
		response.WriteString(scanner.Text() + "\n")
	}

	// Check for errors during scanning
	if err = scanner.Err(); err != nil {
		err = fmt.Errorf("error reading response: %w", err)
		return rawWhois, fmt.Errorf("error reading response: %w", err)
	}

	rawWhois = response.String()

	return rawWhois, err
}

// getTLDServerFromCache returns the WHOIS server for the specified TLD from the cache.
func (wl *WhoisLookup) getTLDServerFromCache(tld string) (tldWhoisServer string) {
	wl.m.RLock()
	defer wl.m.RUnlock()

	if rootCache, ok := wl.rootWhoisServers[tld]; ok {
		if rootCache.LastUpdated.Before(time.Now().Add(-wl.config.RootCacheDuration)) {
			// Cache is stale, return empty string
			return tldWhoisServer
		} else {
			tldWhoisServer = rootCache.Host
			return tldWhoisServer
		}
	}
	return tldWhoisServer
}

func (wl *WhoisLookup) setTLDServerToCache(tld string, whoisServer string) {
	wl.m.Lock()
	defer wl.m.Unlock()

	wl.rootWhoisServers[tld] = rootTLDCache{Host: whoisServer, LastUpdated: time.Now()}
}

// getWhoisServerForTLD queries the IANA WHOIS server for the specified TLD
// and returns the WHOIS server associated with that TLD.
func (wl *WhoisLookup) getWhoisServerForTLD(ctx context.Context, tld string) (whoisServer string, err error) {

	whoisServer = wl.getTLDServerFromCache(tld)

	if whoisServer != "" {
		return whoisServer, nil
	}

	// Connect to IANA WHOIS server
	var (
		dialer = net.Dialer{
			Timeout: wl.config.DefaultTimeout,
		}
		conn net.Conn
	)

	if conn, err = dialer.DialContext(ctx, "tcp", wl.config.WhoisTLDServer); err != nil {
		err = fmt.Errorf("dialer.DialContext() error:%w", err)
		return whoisServer, err
	}
	defer conn.Close()

	// Send the TLD query
	if _, err = conn.Write([]byte(tld + "\r\n")); err != nil {
		err = fmt.Errorf("conn.Write() error:%w", err)
		return whoisServer, err
	}

	// Read the response
	scanner := bufio.NewScanner(conn)
	for scanner.Scan() {
		line := scanner.Text()
		// Look for the line containing the WHOIS server
		if strings.HasPrefix(line, "whois:") {
			// Split and return the WHOIS server URL
			parts := strings.Fields(line)
			if len(parts) > 1 {
				whoisServer = parts[1]
				wl.setTLDServerToCache(tld, whoisServer)
				return whoisServer, nil
			}
		}
	}

	if err = scanner.Err(); err != nil {
		err = fmt.Errorf("error reading WHOIS response: %w", err)
		return whoisServer, err
	}

	err = ErrWhoisServerNotFound
	err = fmt.Errorf("%w for TLD: %s", err, tld)

	return "", fmt.Errorf("WHOIS server not found for TLD: %s", tld)
}

// wrapParser by wrapping the output of whoisparser.WhoisInfo the underlying parser can be changed without affecting the output
func wrapParser(whoisRaw string) (info WhoisInfo, err error) {

	var whoisInfoP whoisparser.WhoisInfo

	if whoisInfoP, err = whoisparser.Parse(whoisRaw); err != nil {
		err = fmt.Errorf("whoisparser.Parse() error:%w", err)
		return info, err
	}

	if whoisInfoP.Domain != nil {
		info.Domain = &Domain{
			ID:                   whoisInfoP.Domain.ID,
			Domain:               whoisInfoP.Domain.Domain,
			Punycode:             whoisInfoP.Domain.Punycode,
			Name:                 whoisInfoP.Domain.Name,
			Extension:            whoisInfoP.Domain.Extension,
			WhoisServer:          whoisInfoP.Domain.WhoisServer,
			Status:               whoisInfoP.Domain.Status,
			NameServers:          whoisInfoP.Domain.NameServers,
			DNSSec:               whoisInfoP.Domain.DNSSec,
			CreatedDate:          whoisInfoP.Domain.CreatedDate,
			CreatedDateInTime:    whoisInfoP.Domain.CreatedDateInTime,
			UpdatedDate:          whoisInfoP.Domain.UpdatedDate,
			UpdatedDateInTime:    whoisInfoP.Domain.UpdatedDateInTime,
			ExpirationDate:       whoisInfoP.Domain.ExpirationDate,
			ExpirationDateInTime: whoisInfoP.Domain.ExpirationDateInTime,
		}
	}

	if whoisInfoP.Registrar != nil {
		info.Registrar = convertContact(whoisInfoP.Billing)
	}

	if whoisInfoP.Registrant != nil {
		info.Registrant = convertContact(whoisInfoP.Registrant)
	}

	if whoisInfoP.Administrative != nil {
		info.Administrative = convertContact(whoisInfoP.Administrative)
	}

	if whoisInfoP.Technical != nil {
		info.Technical = convertContact(whoisInfoP.Technical)
	}

	if whoisInfoP.Billing != nil {
		info.Billing = convertContact(whoisInfoP.Billing)
	}

	return info, err
}

func convertContact(contact *whoisparser.Contact) (c *Contact) {
	if contact != nil {
		c = &Contact{
			ID:           contact.ID,
			Name:         contact.Name,
			Organization: contact.Organization,
			Street:       contact.Street,
			City:         contact.City,
			Province:     contact.Province,
			PostalCode:   contact.PostalCode,
			Country:      contact.Country,
			Phone:        contact.Phone,
			PhoneExt:     contact.PhoneExt,
			Fax:          contact.Fax,
			FaxExt:       contact.FaxExt,
			Email:        contact.Email,
			ReferralURL:  contact.ReferralURL,
		}
	}
	return c
}
