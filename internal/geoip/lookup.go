package geoip

import (
	"net"
	"strings"
	"sync"

	"ads-httpproxy/pkg/logging"

	"github.com/oschwald/maxminddb-golang"
	"go.uber.org/zap"
)

type Lookup struct {
	db   *maxminddb.Reader
	mu   sync.RWMutex
	path string
}

func NewLookup(path string) (*Lookup, error) {
	db, err := maxminddb.Open(path)
	if err != nil {
		return nil, err
	}

	logging.Logger.Info("Loaded GeoIP database", zap.String("path", path))
	return &Lookup{
		db:   db,
		path: path,
	}, nil
}

func (l *Lookup) Close() {
	if l.db != nil {
		l.db.Close()
	}
}

// GetCountry returns the ISO country code for an IP
func (l *Lookup) GetCountry(ipStr string) (string, error) {
	l.mu.RLock()
	defer l.mu.RUnlock()

	host, _, err := net.SplitHostPort(ipStr)
	if err == nil {
		ipStr = host
	}

	ip := net.ParseIP(ipStr)
	if ip == nil {
		return "", nil
	}

	var record struct {
		Country struct {
			ISOCode string `maxminddb:"iso_code"`
		} `maxminddb:"country"`
	}

	err = l.db.Lookup(ip, &record)
	if err != nil {
		return "", err
	}

	return record.Country.ISOCode, nil
}

// IsAllowed checks if the IP is allowed based on allow/block lists
// Empty lists mean allowed (unless blocked is matched)
func (l *Lookup) IsAllowed(ipStr string, allowList, blockList []string) bool {
	country, err := l.GetCountry(ipStr)
	if err != nil {
		logging.Logger.Error("GeoIP lookup failed", zap.Error(err))
		return true // Fail open?
	}

	country = strings.ToUpper(country)

	// Block list takes precedence
	for _, c := range blockList {
		if strings.ToUpper(c) == country {
			return false
		}
	}

	// If allow list is present, must be in it
	if len(allowList) > 0 {
		for _, c := range allowList {
			if strings.ToUpper(c) == country {
				return true
			}
		}
		return false
	}

	return true
}
