package main

import (
	"fmt"
	"html/template"
	"net"
	"net/http"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/miekg/dns"
	"github.com/sirupsen/logrus"
	"github.com/weppos/publicsuffix-go/publicsuffix"
)

var log = logrus.New()

type DomainPattern struct {
	Pattern *regexp.Regexp // Regex pattern to match domain
	Action  string         // Record type, e.g., A, CNAME, TXT
	Target  string         // Target value for the record
	TTL     uint32         // Optional: TTL for this record
}

type Config struct {
	Email          string
	CNAMEServer    string
	NSRecords      []string
	SOAEmail       string
	SOAPrimary     string
	DefaultTTL     uint32
	NS_TTL         uint32
	SOA_TTL        uint32
	CNAME_TTL      uint32
	Blacklist      []string        // Blacklist for domains
	DomainPatterns []DomainPattern // Patterns for special DNS handling
}

var config Config

func notFoundHandler(c *gin.Context) {
	c.Header("Content-Type", "text/html")
	c.Header("Cache-Control", "public, max-age=3600")
	c.String(http.StatusNotFound, `<meta http-equiv="refresh" content="0; url=/" />`)
}

func UnFqdn(fqdn string) string {
	if strings.HasSuffix(fqdn, ".") {
		return fqdn[:len(fqdn)-1]
	}
	return fqdn
}

func getDomain(host string) (string, error) {
	host = strings.ToLower(UnFqdn(host))
	domain, err := publicsuffix.Domain(host)
	if err != nil {
		log.WithError(err).WithField("host", host).Error("Failed to extract domain")
		return "", err
	}
	return domain, nil
}

func isDomainBlacklisted(domain string) bool {
	for _, blacklisted := range config.Blacklist {
		if strings.EqualFold(blacklisted, domain) {
			return true
		}
	}
	return false
}

func domainHandler(c *gin.Context) {
	host := c.Request.Host
	if net.ParseIP(host) != nil {
		c.Status(http.StatusForbidden)
		return
	}
	domain, err := getDomain(host)
	if err != nil {
		c.Status(http.StatusForbidden)
		return
	}
	domain = strings.ToUpper(domain)
	// 检查域名是否在黑名单中
	if isDomainBlacklisted(domain) {
		c.Status(http.StatusForbidden)
		return
	}
	tmpl, err := template.ParseFiles("template.html")
	if err != nil {
		log.WithError(err).Error("Failed to parse template")
		c.String(http.StatusInternalServerError, "无法渲染页面")
		return
	}

	c.Header("X-Frame-Options", "DENY")
	c.Header("X-Content-Type-Options", "nosniff")
	c.Header("X-XSS-Protection", "1; mode=block")

	if c.Request.URL.Path != "/" {
		c.Header("Content-Type", "text/html")
		c.String(http.StatusOK, `<meta http-equiv="refresh" content="0; url=/" />`)
		return
	}

	if err := tmpl.Execute(c.Writer, struct {
		Domain string
		Email  string
	}{
		Domain: domain,
		Email:  config.Email,
	}); err != nil {
		log.WithError(err).Error("Template execution failed")
		c.String(http.StatusInternalServerError, "Internal Server Error")
		return
	}
}

// Starts the HTTP server
func startHTTPServer() {
	// Create a Gin router instance
	gin.SetMode(gin.ReleaseMode)
	r := gin.Default()
	// Define routes
	r.GET("/", domainHandler)
	r.NoRoute(notFoundHandler)
	log.Info("Starting HTTP server on port 8080...")
	err := r.Run("0.0.0.0:8080")
	if err != nil {
		log.WithError(err).Fatal("HTTP server error")
	}
}

func startDNSServer() {
	server := &dns.Server{Addr: ":53", Net: "udp"}
	dns.HandleFunc(".", handleDNSRequest)
	log.Info("Starting DNS server on port 53...")
	if err := server.ListenAndServe(); err != nil {
		log.WithError(err).Fatal("Failed to start DNS server")
	}
}

func handleDNSRequest(w dns.ResponseWriter, r *dns.Msg) {
	msg := new(dns.Msg)
	msg.SetReply(r)
	msg.Authoritative = true

	for _, q := range r.Question {
		domain, err := getDomain(q.Name)
		if err != nil || domain == "" {
			log.WithFields(logrus.Fields{
				"query_name": q.Name,
				"error":      err,
			}).Warn("Domain extraction failed or domain is empty")
			return
		}
		// First, check for exact matches before falling back to regex patterns
		foundMatch := false

		for _, pattern := range config.DomainPatterns {
			if pattern.Pattern.MatchString(strings.ToLower(UnFqdn(q.Name))) {
				log.WithFields(logrus.Fields{
					"pattern": pattern.Pattern.String(),
					"query":   strings.ToLower(UnFqdn(q.Name)),
				}).Info("Pattern matched")
				handleSpecialDNSRecord(msg, q.Name, pattern.Action, pattern.Target)
				foundMatch = true
				break
			}
		}

		if !foundMatch {
			//log.WithField("query_name", q.Name).Info("No matching pattern found")
			switch q.Qtype {
			case dns.TypeNS:
				handleNS(msg, domain)
			case dns.TypeSOA:
				handleSOA(msg, domain)
			default:
				handleCNAME(msg, q.Name)
			}
		}

		w.WriteMsg(msg)
	}
}

func handleSpecialDNSRecord(msg *dns.Msg, name string, recordType string, target string) {
	var rr dns.RR
	var err error

	switch recordType {
	case "A":
		rr, err = dns.NewRR(fmt.Sprintf("%s A %s", name, target))
	case "CNAME":
		rr, err = dns.NewRR(fmt.Sprintf("%s CNAME %s.", name, target))
	case "TXT":
		rr, err = dns.NewRR(fmt.Sprintf("%s TXT \"%s\"", name, target))
	default:
		log.WithField("record_type", recordType).Warn("Unsupported record type")
		return
	}

	if err == nil {
		rr.Header().Ttl = config.CNAME_TTL
		msg.Answer = append(msg.Answer, rr)
	} else {
		log.WithError(err).Error("Failed to create DNS record")
	}
}

func handleNS(msg *dns.Msg, domain string) {
	for _, ns := range config.NSRecords {
		rr, err := dns.NewRR(fmt.Sprintf("%s NS %s", domain, ns))
		if err == nil {
			rr.Header().Ttl = config.NS_TTL
			msg.Answer = append(msg.Answer, rr)
		}
	}
}

func handleSOA(msg *dns.Msg, domain string) {
	serial := time.Now().Format("20060102") + "01"
	soaEmailFormatted := strings.Replace(config.SOAEmail, "@", ".", 1)
	soa := fmt.Sprintf("%s. %s. %s 7200 3600 1209600 3600", config.SOAPrimary, soaEmailFormatted, serial)
	rr, err := dns.NewRR(fmt.Sprintf("%s SOA %s", domain, soa))
	if err == nil {
		rr.Header().Ttl = config.SOA_TTL
		msg.Answer = append(msg.Answer, rr)
	}
}

func handleCNAME(msg *dns.Msg, name string) {
	rr, err := dns.NewRR(fmt.Sprintf("%s CNAME %s.", name, config.CNAMEServer))
	if err == nil {
		rr.Header().Ttl = config.CNAME_TTL
		msg.Answer = append(msg.Answer, rr)
	}
}

func parseDomainPatterns() []DomainPattern {
	patternsEnv := os.Getenv("DOMAIN_PATTERNS")
	if patternsEnv == "" {
		return nil
	}

	var patterns []DomainPattern
	patternStrings := strings.Split(patternsEnv, ",")
	for _, patternStr := range patternStrings {
		parts := strings.Split(patternStr, ":")
		if len(parts) != 3 {
			log.WithField("pattern", patternStr).Warn("Invalid domain pattern format")
			continue
		}

		pattern := regexp.MustCompile(parts[0])
		patterns = append(patterns, DomainPattern{
			Pattern: pattern,
			Action:  parts[1],
			Target:  parts[2],
			TTL:     config.CNAME_TTL,
		})
	}
	return patterns
}

func main() {
	log.SetFormatter(&logrus.JSONFormatter{})
	config.Email = os.Getenv("CONTACT_EMAIL")
	config.CNAMEServer = os.Getenv("CNAME_TARGET")
	config.NSRecords = strings.Split(os.Getenv("NS_RECORDS"), ",")
	config.SOAEmail = os.Getenv("SOA_EMAIL")
	config.SOAPrimary = os.Getenv("SOA_PRIMARY")
	config.DomainPatterns = parseDomainPatterns()

	config.DefaultTTL = 300
	config.NS_TTL = 86400
	config.SOA_TTL = 86400
	config.CNAME_TTL = 3600

	blacklist := os.Getenv("DOMAIN_BLACKLIST")
	if blacklist != "" {
		config.Blacklist = strings.Split(blacklist, ",")
	}

	if config.Email == "" || config.CNAMEServer == "" || len(config.NSRecords) == 0 || config.SOAEmail == "" || config.SOAPrimary == "" {
		log.Fatal("Missing required environment variables: CONTACT_EMAIL, CNAME_TARGET, NS_RECORDS, SOA_EMAIL, SOA_PRIMARY")
	}

	go startHTTPServer()
	go startDNSServer()

	select {}
}
