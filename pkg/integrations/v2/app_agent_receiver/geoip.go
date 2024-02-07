package app_agent_receiver

import (
	"fmt"
	"net"
	"time"

	"github.com/go-kit/log"
	"github.com/go-kit/log/level"
	"github.com/oschwald/geoip2-golang"
	"github.com/prometheus/client_golang/prometheus"
)

const (
	ErrEmptyDBPathGeoIPConfig = "db path cannot be empty when geoip is enabled"
	ErrEmptyDBTypeGeoIPConfig = "db type should be either city or as when geoip is enabled"
)

// GeoIPProvider is interface for providing geoip information via a locally mounted GeoIP database.
type GeoIPProvider interface {
	TransformMetas(mt *Meta, sourceIP net.IP) *Meta
}

// GeoIPProvider is a wrapper for the MaxMind geoip2.Reader
type GeoIP2 struct {
	logger  log.Logger
	db      *geoip2.Reader
	cfgs    *GeoIPConfig
	metrics *geoipMetrics
}

type geoipMetrics struct {
	requests        *prometheus.CounterVec
	errors          *prometheus.CounterVec
	requestDuration *prometheus.SummaryVec
}

// NewGeoIPProvider creates an instance of GeoIPProvider.
func NewGeoIPProvider(l log.Logger, config GeoIPConfig, reg prometheus.Registerer) GeoIPProvider {

	err := validateGeoIPConfig(&config)
	if err != nil {
		panic(err) //TODO Is panicing the correct way to handle this?
	}

	var db *geoip2.Reader

	if config.Enabled {
		db, err = geoip2.Open(config.DB)
		if err != nil {
			panic(err) //TODO Is panicing the correct way to handle this?
		}
	}

	// instantiate and register metrics
	metrics := &geoipMetrics{
		requests: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "app_agent_receiver_geoip_requests_total",
			Help: "Total number of requests to the GeoIP database",
		}, []string{"geoip_provider"}),
		errors: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "app_agent_receiver_geoip_errors_total",
			Help: "Total number of errors from GeoIP database",
		}, []string{"geoip_provider"}),
		requestDuration: prometheus.NewSummaryVec(prometheus.SummaryOpts{
			Name:       "app_agent_receiver_geoip_request_duration_seconds",
			Help:       "The duration of the requests to the GeoIP database",
			Objectives: map[float64]float64{0.5: 0.05, 0.9: 0.01, 0.99: 0.001},
		}, []string{"geoip_provider"}),
	}
	reg.MustRegister(metrics.requests, metrics.errors, metrics.requestDuration)

	return &GeoIP2{
		logger:  l,
		db:      db,
		cfgs:    &config,
		metrics: metrics,
	}
}

func validateGeoIPConfig(c *GeoIPConfig) error {
	if c != nil && c.Enabled {
		if c.DB == "" {
			return fmt.Errorf(ErrEmptyDBPathGeoIPConfig)
		}

		if c.DBType == "" {
			return fmt.Errorf(ErrEmptyDBTypeGeoIPConfig)
		}
	}

	return nil
}

// getGeoIPData will query the geoip2 database for the given IP address and return the geoip2.City record.
func (gp *GeoIP2) getGeoIPData(sourceIP net.IP) (*geoip2.City, error) {

	start := time.Now()
	record, err := gp.db.City(sourceIP)
	elapsed := time.Since(start).Seconds()

	gp.metrics.requestDuration.WithLabelValues("MaxMind").Observe(elapsed)

	if err != nil {
		gp.metrics.errors.WithLabelValues("MaxMind").Inc()
		return nil, err
	}
	gp.metrics.requests.WithLabelValues("MaxMind").Inc()

	// Validate record has appropriate data
	_, ok := record.Country.Names["en"]
	if !ok {
		gp.metrics.errors.WithLabelValues("MaxMind").Inc()
		return nil, fmt.Errorf("no English name for country")
	}

	_, ok = record.City.Names["en"]
	if !ok {
		gp.metrics.errors.WithLabelValues("MaxMind").Inc()
		return nil, fmt.Errorf("no English name for city")
	}

	_, ok = record.Continent.Names["en"]
	if !ok {
		gp.metrics.errors.WithLabelValues("MaxMind").Inc()
		return nil, fmt.Errorf("no English name for continent")
	}

	if len(record.Subdivisions) > 0 {
		_, ok = record.Subdivisions[0].Names["en"] // TODO: Copilot generated first. Example has last index.
		if !ok {
			gp.metrics.errors.WithLabelValues("MaxMind").Inc()
			return nil, fmt.Errorf("no English name for subdivision")
		}
	}

	return record, nil
}

// mapGeoIP2CityToMetas will map the geoip2.City record to the app_agent_receiver.Metas.GeoIP struct.
// This method assumes that the record has been validated and is not nil.
func mapGeoIP2CityToMetas(mt *Meta, record *geoip2.City, clientIP net.IP) (*Meta, error) {

	country, _ := record.Country.Names["en"]
	city, _ := record.City.Names["en"]
	continent, _ := record.Continent.Names["en"]
	subdivisionName, subdivisionCode := "", ""
	if len(record.Subdivisions) > 0 {
		subdivisionName, _ = record.Subdivisions[0].Names["en"] // TODO: Copilot generated first. Example has last index.
		subdivisionCode = record.Subdivisions[0].IsoCode
	}

	mt.Geo = Geo{
		ClientIP:        clientIP,
		LocationLat:     record.Location.Latitude,
		LocationLong:    record.Location.Longitude,
		CityName:        city,
		CountryName:     country,
		ContinentName:   continent,
		ContinentCode:   record.Continent.Code,
		PostalCode:      record.Postal.Code,
		Timezone:        record.Location.TimeZone,
		SubdivisionName: subdivisionName,
		SubdivisionCode: subdivisionCode,
	}

	return mt, nil
}

func isValidIP(ip net.IP) bool {
	// net.IP is a slice of bytes. The length of the slice is the number of bytes in the IP address.
	// for IPV4 the length is 4 and for IPV6 the length is 16.
	private10 := ip[0] == 10  // private IP
	localhost := ip[0] == 127 // localhost
	return !private10 && !localhost
}

// TransformException will attempt to populate the metas with geo IP data. If the geo IP data is not available, the
// metas will be returned as is.
func (gp *GeoIP2) TransformMetas(mt *Meta, clientIP net.IP) *Meta {
	if clientIP == nil {
		level.Warn(gp.logger).Log("msg", "Client IP is nil")
		return mt
	}

	// Validate IP is in the correct format. For example ignore ::1, or 10.x.x.x ips.
	if !isValidIP(clientIP) {
		level.Warn(gp.logger).Log("msg", "Client IP is not a valid public IP")
		return mt
	}
	level.Info(gp.logger).Log("msg", "original client ip was", "client_ip", clientIP.String())

	// Query GeoIP db
	geoIpCityRecord, err := gp.getGeoIPData(clientIP)
	if err != nil {
		level.Error(gp.logger).Log("msg", "Error querying geo IP2 database", "err", err)
		return mt
	}

	//  Populate metas with geo IP data
	transformedMeta, err := mapGeoIP2CityToMetas(mt, geoIpCityRecord, clientIP)
	if err != nil {
		level.Error(gp.logger).Log("msg", "Error populating metas with geo IP data", "err", err)
		return mt
	}

	return transformedMeta
}
