package header_transform

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"regexp"
	"strings"
)

// Rule struct so that we get traefik config
type Rule struct {
	Name         string       `yaml:"Name"`
	Header       string       `yaml:"Header"`
	Value        string       `yaml:"Value"`
	Values       []string     `yaml:"Values"`
	HeaderPrefix string       `yaml:"HeaderPrefix"`
	Sep          string       `yaml:"Sep"`
	Type         string       `yaml:"Type"`
	TrustedCIDR  []*net.IPNet `yaml:"TrustedCIDR"`
}

type InRule struct {
	Name         string   `yaml:"Name"`
	Header       string   `yaml:"Header"`
	Value        string   `yaml:"Value"`
	Values       []string `yaml:"Values"`
	HeaderPrefix string   `yaml:"HeaderPrefix"`
	Sep          string   `yaml:"Sep"`
	Type         string   `yaml:"Type"`
	TrustedCIDR  []string `yaml:"TrustedCIDR"`
}

// Config holds configuration to be passed to the plugin
type Config struct {
	Rules []InRule
}

// CreateConfig populates the Config data object
func CreateConfig() *Config {
	return &Config{
		Rules: []InRule{},
	}
}

// HeadersTransformation holds the necessary components of a Traefik plugin
type HeadersTransformation struct {
	next  http.Handler
	rules []Rule
	name  string
}

// Convert InRule to Rule
func (in *InRule) toRule() Rule {
	var nets []*net.IPNet
	for _, v := range in.TrustedCIDR {
		_, ip, err := net.ParseCIDR(v)
		if err != nil {
			// If CIDR is not correct, ignore and continue
			continue
		}
		nets = append(nets, ip)
	}
	rule := Rule{
		in.Name,
		in.Header,
		in.Value,
		in.Values,
		in.HeaderPrefix,
		in.Sep,
		in.Type,
		nets,
	}
	return rule
}

// New instantiates and returns the required components used to handle a HTTP request
func New(ctx context.Context, next http.Handler, config *Config, name string) (http.Handler, error) {
	var rules []Rule
	for _, rule := range config.Rules {
		if rule.Header == "" || rule.Type == "" {
			return nil, fmt.Errorf("can't use '%s', header and type cannot be empty",
				rule.Name)
		}
		if rule.Type == "Set" && rule.Sep == "" && ((rule.Value != "" && len(rule.Values) > 0) || len(rule.Values) > 1) {
			return nil, fmt.Errorf("can't use '%s', specify Sep with more than one value to set",
				rule.Name)
		}
		if rule.Value == "" && len(rule.Values) == 0 {
			if rule.Type == "Set" {
				return nil, fmt.Errorf("can't use '%s', specify either Value or Values",
					rule.Name)
			}
			if rule.HeaderPrefix != "" {
				return nil, fmt.Errorf("can't use '%s', cannot set HeaderPrefix without passing in Value/Values",
					rule.Name)
			}
		}
		rules = append(rules, rule.toRule())
	}
	return &HeadersTransformation{
		rules: rules,
		next:  next,
		name:  name,
	}, nil
}

// Iterate over every headers to match the ones specified in the config and
// return nothing if regexp failed.
func (u *HeadersTransformation) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	for _, rule := range u.rules {
		// Check if the last hop IP is in the allowed IP list
		if rule.trustIP(req.RemoteAddr) {
			switch rule.Type {
			case "Rename":
				for headerName, headerValues := range req.Header {
					matched, err := regexp.Match(rule.Header, []byte(headerName))
					if err != nil {
						http.Error(rw, err.Error(), http.StatusInternalServerError)
						return
					}
					if matched {
						req.Header.Del(headerName)
						for _, val := range headerValues {
							req.Header.Set(getValue(rule.Value, rule.HeaderPrefix, req), val)
						}
					}
				}
			case "Set":
				// Set to value, and append values if present. Either of them can be empty
				tmp_val := getValue(rule.Value, rule.HeaderPrefix, req)
				if len(rule.Values) != 0 {
					for _, value := range rule.Values {
						if tmp_val != "" {
							tmp_val += rule.Sep
						}
						tmp_val += getValue(value, rule.HeaderPrefix, req)
					}
				}
				req.Header.Set(rule.Header, tmp_val)
			case "Del":
				req.Header.Del(rule.Header)
			default:
			}
		}
	}
	u.next.ServeHTTP(rw, req)
}

// getValue checks if prefix exists, the given prefix is present, and then proceeds to read the existing header (after stripping the prefix) to return as value
func getValue(ruleValue, vauleIsHeaderPrefix string, req *http.Request) string {
	actualValue := ruleValue
	if vauleIsHeaderPrefix != "" && strings.HasPrefix(ruleValue, vauleIsHeaderPrefix) {
		header := strings.TrimPrefix(ruleValue, vauleIsHeaderPrefix)
		// If the resulting value after removing the prefix is empty (value was only prefix), we return the actual value, which is the prefix itself.
		// This is because doing a req.Header.Get("") would not fly well.
		if header != "" {
			actualValue = req.Header.Get(header)
		}
	}
	return actualValue
}

func (r *Rule) trustIP(s string) bool {
	temp, _, err := net.SplitHostPort(s)
	if err != nil {
		return true
	}
	ip := net.ParseIP(temp)

	// If no trusted IPs are provided, all IPs are trusted
	if len(r.TrustedCIDR) == 0 {
		return true
	}

	// Check if the previous hop belongs to one of the trusted IP ranges
	for _, network := range r.TrustedCIDR {
		if network.Contains(ip) {
			return true
		}
	}
	return false
}
