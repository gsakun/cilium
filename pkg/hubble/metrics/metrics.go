// Copyright 2019 Authors of Hubble
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package metrics

import (
	"fmt"
	"net/http"

	v1 "github.com/cilium/cilium/pkg/hubble/api/v1"
	"github.com/cilium/cilium/pkg/hubble/metrics/api"
	_ "github.com/cilium/cilium/pkg/hubble/metrics/dns"               // invoke init
	_ "github.com/cilium/cilium/pkg/hubble/metrics/drop"              // invoke init
	_ "github.com/cilium/cilium/pkg/hubble/metrics/flow"              // invoke init
	_ "github.com/cilium/cilium/pkg/hubble/metrics/http"              // invoke init
	_ "github.com/cilium/cilium/pkg/hubble/metrics/icmp"              // invoke init
	_ "github.com/cilium/cilium/pkg/hubble/metrics/port-distribution" // invoke init
	_ "github.com/cilium/cilium/pkg/hubble/metrics/tcp"               // invoke init

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	dto "github.com/prometheus/client_model/go"
	"github.com/sirupsen/logrus"
)

var (
	enabledMetrics api.Handlers
	registry       = prometheus.NewPedanticRegistry()
)

// ProcessFlow processes a flow and updates metrics
func ProcessFlow(flow v1.Flow) {
	if enabledMetrics != nil {
		enabledMetrics.ProcessFlow(flow)
	}
}

// Init initialies the metrics system
func Init(address string, enabled api.Map) (<-chan error, error) {
	e, err := api.DefaultRegistry().ConfigureHandlers(registry, enabled)
	if err != nil {
		return nil, err
	}
	enabledMetrics = e

	errChan := make(chan error, 1)

	go func() {
		mux := http.NewServeMux()
		mux.Handle("/metrics", promhttp.HandlerFor(registry, promhttp.HandlerOpts{
			FilterGenerator: filterGenerator,
		}))
		srv := http.Server{
			Addr:    address,
			Handler: mux,
		}
		errChan <- srv.ListenAndServe()
	}()

	return errChan, nil
}

// EnableMetrics starts the metrics server with a given list of metrics. This is the
// function Cilium uses to configure Hubble metrics in embedded mode.
func EnableMetrics(log logrus.FieldLogger, metricsServer string, m []string) error {
	errChan, err := Init(metricsServer, api.ParseMetricList(m))
	if err != nil {
		return fmt.Errorf("unable to setup metrics: %v", err)
	}
	go func() {
		err := <-errChan
		if err != nil {
			log.WithError(err).Error("Unable to initialize metrics server")
		}
	}()
	return nil
}

func filterGenerator(req *http.Request) prometheus.GatherFilter {
	opts := req.URL.Query()
	var (
		sourceValue *string
		destValue   *string
	)
	if sourceVs, ok := opts[api.Source]; ok && len(sourceVs) == 1 {
		sourceValue = &sourceVs[0]
	}
	if destVs, ok := opts[api.Destination]; ok && len(destVs) == 1 {
		destValue = &destVs[0]
	}

	return func(metric *dto.Metric) bool {
		var (
			sourceMatch = sourceValue == nil
			destMatch   = destValue == nil
		)
		for _, l := range metric.Label {
			if !sourceMatch &&
				l.GetName() == api.Source &&
				l.GetValue() == *sourceValue {
				sourceMatch = true
			}
			if !destMatch &&
				l.GetName() == api.Destination &&
				l.GetValue() == *destValue {
				destMatch = true
			}
		}
		return sourceMatch && destMatch
	}
}
