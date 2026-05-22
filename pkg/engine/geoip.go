package engine

import (
	"net"
	"github.com/oschwald/geoip2-golang"
)

type GeoIP struct {
	db *geoip2.Reader
}

func NewGeoIP(dbPath string) (*GeoIP, error) {
	// For sandbox, we provide a safe fallback if DB is missing
	db, err := geoip2.Open(dbPath)
	if err != nil {
		return &GeoIP{}, nil
	}
	return &GeoIP{db: db}, nil
}

func (g *GeoIP) GetCountry(ipStr string) string {
	if g.db == nil {
		return "Unknown"
	}
	ip := net.ParseIP(ipStr)
	record, err := g.db.Country(ip)
	if err != nil {
		return "Unknown"
	}
	return record.Country.IsoCode
}
