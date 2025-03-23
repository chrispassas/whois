## Whois performs whois lookups on domains. In addition to raw it also returns a parsed structure of the whois data.

## Quick example
```go
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
```

## JSON Output
```json
{
  "domain": {
    "id": "1264983250_DOMAIN_COM-VRSN",
    "domain": "github.com",
    "punycode": "github.com",
    "name": "github",
    "extension": "com",
    "whois_server": "whois.markmonitor.com",
    "status": [
      "clientUpdateProhibited",
      "clientTransferProhibited",
      "clientDeleteProhibited"
    ],
    "name_servers": [
      "ns-520.awsdns-01.net",
      "dns3.p08.nsone.net",
      "dns2.p08.nsone.net",
      "ns-1707.awsdns-21.co.uk",
      "ns-421.awsdns-52.com",
      "dns1.p08.nsone.net",
      "dns4.p08.nsone.net",
      "ns-1283.awsdns-32.org"
    ],
    "created_date": "2007-10-09T18:20:50+0000",
    "updated_date": "2024-09-07T09:16:33+0000",
    "expiration_date": "2026-10-09T00:00:00+0000"
  },
  "registrant": {
    "organization": "GitHub, Inc.",
    "province": "CA",
    "country": "US",
    "email": "select request email form at https://domains.markmonitor.com/whois/github.com"
  },
  "administrative": {
    "organization": "GitHub, Inc.",
    "province": "CA",
    "country": "US",
    "email": "select request email form at https://domains.markmonitor.com/whois/github.com"
  },
  "technical": {
    "organization": "GitHub, Inc.",
    "province": "CA",
    "country": "US",
    "email": "select request email form at https://domains.markmonitor.com/whois/github.com"
  }
}
```

## Raw Output
```
Domain Name: github.com
Registry Domain ID: 1264983250_DOMAIN_COM-VRSN
Registrar WHOIS Server: whois.markmonitor.com
Registrar URL: http://www.markmonitor.com
Updated Date: 2024-09-07T09:16:33+0000
Creation Date: 2007-10-09T18:20:50+0000
Registrar Registration Expiration Date: 2026-10-09T00:00:00+0000
Registrar: MarkMonitor, Inc.
Registrar IANA ID: 292
Registrar Abuse Contact Email: abusecomplaints@markmonitor.com
Registrar Abuse Contact Phone: +1.2086851750
Domain Status: clientUpdateProhibited (https://www.icann.org/epp#clientUpdateProhibited)
Domain Status: clientTransferProhibited (https://www.icann.org/epp#clientTransferProhibited)
Domain Status: clientDeleteProhibited (https://www.icann.org/epp#clientDeleteProhibited)
Registrant Organization: GitHub, Inc.
Registrant State/Province: CA
Registrant Country: US
Registrant Email: Select Request Email Form at https://domains.markmonitor.com/whois/github.com
Admin Organization: GitHub, Inc.
Admin State/Province: CA
Admin Country: US
Admin Email: Select Request Email Form at https://domains.markmonitor.com/whois/github.com
Tech Organization: GitHub, Inc.
Tech State/Province: CA
Tech Country: US
Tech Email: Select Request Email Form at https://domains.markmonitor.com/whois/github.com
Name Server: ns-520.awsdns-01.net
Name Server: dns3.p08.nsone.net
Name Server: dns2.p08.nsone.net
Name Server: ns-1707.awsdns-21.co.uk
Name Server: ns-421.awsdns-52.com
Name Server: dns1.p08.nsone.net
Name Server: dns4.p08.nsone.net
Name Server: ns-1283.awsdns-32.org
DNSSEC: unsigned
URL of the ICANN WHOIS Data Problem Reporting System: http://wdprs.internic.net/
>>> Last update of WHOIS database: 2025-03-23T02:57:05+0000 <<<

For more information on WHOIS status codes, please visit:
  https://www.icann.org/resources/pages/epp-status-codes

If you wish to contact this domain’s Registrant, Administrative, or Technical
contact, and such email address is not visible above, you may do so via our web
form, pursuant to ICANN’s Temporary Specification. To verify that you are not a
robot, please enter your email address to receive a link to a page that
facilitates email communication with the relevant contact(s).

Web-based WHOIS:
  https://domains.markmonitor.com/whois

If you have a legitimate interest in viewing the non-public WHOIS details, send
your request and the reasons for your request to whoisrequest@markmonitor.com
and specify the domain name in the subject line. We will review that request and
may ask for supporting documentation and explanation.

The data in MarkMonitor’s WHOIS database is provided for information purposes,
and to assist persons in obtaining information about or related to a domain
name’s registration record. While MarkMonitor believes the data to be accurate,
the data is provided "as is" with no guarantee or warranties regarding its
accuracy.

By submitting a WHOIS query, you agree that you will use this data only for
lawful purposes and that, under no circumstances will you use this data to:
  (1) allow, enable, or otherwise support the transmission by email, telephone,
or facsimile of mass, unsolicited, commercial advertising, or spam; or
  (2) enable high volume, automated, or electronic processes that send queries,
data, or email to MarkMonitor (or its systems) or the domain name contacts (or
its systems).

MarkMonitor reserves the right to modify these terms at any time.

By submitting this query, you agree to abide by this policy.

MarkMonitor Domain Management(TM)
Protecting companies and consumers in a digital world.

Visit MarkMonitor at https://www.markmonitor.com
Contact us at +1.8007459229
In Europe, at +44.02032062220
--
```