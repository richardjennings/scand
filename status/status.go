package status

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/richardjennings/scand/scan"
	"log"
	"net/http"
)

type Status struct {
	statusGuage *prometheus.GaugeVec
}

func NewStatus() *Status {
	s := Status{}
	s.statusGuage = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "scand_result",
			Help: "Gauge of Scand detected vulnerabilities",
		},
		[]string{"security_severity", "id", "image"},
	)
	return &s
}

func (s *Status) Update(result scan.Result) {
	image := result.ImageStatus.ImageSHA()

	if result.Report == nil {
		log.Println("missing sarif report")
		return
	}
	for _, run := range result.Report.Runs {
		if run.Tool.Driver == nil {
			log.Println("missing data from sarif report")
			return
		}
		for _, rule := range run.Tool.Driver.Rules {
			id := rule.ID
			var severity string

			if _, ok := rule.Properties["security-severity"]; ok {
				severity, _ = rule.Properties["security-severity"].(string)
			}

			s.statusGuage.WithLabelValues(severity, id, image)
		}
	}
}

func (s *Status) Handle() error {
	prometheus.MustRegister(s.statusGuage)
	http.Handle("/metrics", promhttp.InstrumentMetricHandler(
		prometheus.DefaultRegisterer, http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
			promhttp.HandlerFor(prometheus.DefaultGatherer, promhttp.HandlerOpts{}).ServeHTTP(rw, r)
		}),
	))
	return http.ListenAndServe(":8083", nil)
}
