// Copyright 2019-2020 Authors of Cilium
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
	"context"
	"net/http"

	"github.com/cilium/cilium/api/v1/operator/models"
	operatorOption "github.com/cilium/cilium/operator/option"
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/logging/logfields"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	dto "github.com/prometheus/client_model/go"
)

var (
	log = logging.DefaultLogger.WithField(logfields.LogSubsys, "metrics")
)

// Namespace is the namespace key to use for cilium operator metrics.
const Namespace = "cilium_operator"

var (
	// Registry is the global prometheus registry for cilium-operator metrics.
	Registry   *prometheus.Registry
	shutdownCh chan struct{}
)

// Register registers metrics for cilium-operator.
func Register() {
	log.Info("Registering Operator metrics")

	Registry = prometheus.NewPedanticRegistry()
	registerMetrics()

	m := http.NewServeMux()
	m.Handle("/metrics", promhttp.HandlerFor(Registry, promhttp.HandlerOpts{}))
	srv := &http.Server{
		Addr:    operatorOption.Config.OperatorPrometheusServeAddr,
		Handler: m,
	}

	shutdownCh = make(chan struct{})
	go func() {
		go func() {
			err := srv.ListenAndServe()
			switch err {
			case http.ErrServerClosed:
				log.Info("Metrics server shutdown successfully")
				return
			default:
				log.WithError(err).Fatal("Metrics server ListenAndServe failed")
			}
		}()

		<-shutdownCh
		log.Info("Received shutdown signal")
		if err := srv.Shutdown(context.TODO()); err != nil {
			log.WithError(err).Error("Shutdown operator metrics server failed")
		}
	}()
}

// Unregister shuts down the metrics server.
func Unregister() {
	log.Info("Shutting down metrics server")

	if shutdownCh == nil {
		return
	}

	shutdownCh <- struct{}{}
}

var (
	// IdentityGCSize records the identity GC results
	IdentityGCSize *prometheus.GaugeVec

	// IdentityGCRuns records how many times identity GC has run
	IdentityGCRuns *prometheus.GaugeVec

	// CiliumEndpointBatchDensity indicates the number of CEPs batched in a CEB and it used to
	// collect the number of CEPs in CEB at various buckets. For example,
	// number of CEBs in the CEP range <0, 10>
	// number of CEBs in the CEP range <11, 20>
	// number of CEBs in the CEP range <21, 30> and so on
	CiliumEndpointBatchDensity *prometheus.HistogramVec

	// CiliumEndpointsChangeCount indicates the total number of CEPs changed for every CEB request sent to k8s-apiserver.
	// This metric is used to collect number of CEP changes happening at various buckets.
	CiliumEndpointsChangeCount *prometheus.HistogramVec

	// CiliumEndpointBatchSyncErrors used to track the total number of errors occurred during syncing CEB with k8s-apiserver.
	CiliumEndpointBatchSyncErrors *prometheus.CounterVec

	// CiliumEndpointBatchQueueDelay measures the time spent by CEB's in the workqueue. This measures time difference between
	// CEB insert in the workqueue and removal from workqueue.
	CiliumEndpointBatchQueueDelay *prometheus.HistogramVec
)

const (
	// LabelStatus marks the status of a resource or completed task
	LabelStatus = "status"

	// LabelOutcome indicates whether the outcome of the operation was successful or not
	LabelOutcome = "outcome"

	// LabelOpcode indicates the kind of CEB metric, could be CEP insert or remove
	LabelOpcode = "opcode"

	// Label values

	// LabelValueOutcomeSuccess is used as a successful outcome of an operation
	LabelValueOutcomeSuccess = "success"

	// LabelValueOutcomeFail is used as an unsuccessful outcome of an operation
	LabelValueOutcomeFail = "fail"

	// LabelValueOutcomeAlive is used as outcome of alive identity entries
	LabelValueOutcomeAlive = "alive"

	// LabelValueOutcomeDeleted is used as outcome of deleted identity entries
	LabelValueOutcomeDeleted = "deleted"

	// LabelValueCEPInsert is used to indicate the number of CEPs inserted in a CEB
	LabelValueCEPInsert = "cepinserted"

	// LabelValueCEPRemove is used to indicate the number of CEPs removed from a CEB
	LabelValueCEPRemove = "cepremoved"
)

func registerMetrics() []prometheus.Collector {
	// Builtin process metrics
	Registry.MustRegister(prometheus.NewProcessCollector(prometheus.ProcessCollectorOpts{Namespace: Namespace}))

	// Custom metrics
	var collectors []prometheus.Collector

	IdentityGCSize = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Namespace: Namespace,
		Name:      "identity_gc_entries_total",
		Help:      "The number of alive and deleted identities at the end of a garbage collector run",
	}, []string{LabelStatus})
	collectors = append(collectors, IdentityGCSize)

	IdentityGCRuns = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Namespace: Namespace,
		Name:      "identity_gc_runs_total",
		Help:      "The number of times identity garbage collector has run",
	}, []string{LabelOutcome})
	collectors = append(collectors, IdentityGCRuns)

	CiliumEndpointBatchDensity = prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Namespace: Namespace,
		Name:      "number_of_ceps_per_ceb",
		Help:      "The number of CEPs batched in a CEB",
	}, []string{})
	collectors = append(collectors, CiliumEndpointBatchDensity)

	CiliumEndpointsChangeCount = prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Namespace: Namespace,
		Name:      "number_of_cep_changes_per_ceb",
		Help:      "The number of changed CEPs in each CEB update",
	}, []string{LabelOpcode})
	collectors = append(collectors, CiliumEndpointsChangeCount)

	CiliumEndpointBatchSyncErrors = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: Namespace,
		Name:      "ceb_sync_errors_total",
		Help:      "Number of CEB sync errors",
	}, []string{})
	collectors = append(collectors, CiliumEndpointBatchSyncErrors)

	CiliumEndpointBatchQueueDelay = prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Namespace: Namespace,
		Name:      "ceb_queueing_delay_seconds",
		Help:      "CiliumEndpointBatch queueing delay in seconds",
	}, []string{})
	collectors = append(collectors, CiliumEndpointBatchQueueDelay)

	Registry.MustRegister(collectors...)

	return collectors
}

// DumpMetrics gets the current Cilium operator metrics and dumps all into a
// Metrics structure. If metrics cannot be retrieved, returns an error.
func DumpMetrics() ([]*models.Metric, error) {
	result := []*models.Metric{}
	if Registry == nil {
		return result, nil
	}

	currentMetrics, err := Registry.Gather()
	if err != nil {
		return result, err
	}

	for _, val := range currentMetrics {

		metricName := val.GetName()
		metricType := val.GetType()

		for _, metricLabel := range val.Metric {
			labels := map[string]string{}
			for _, label := range metricLabel.GetLabel() {
				labels[label.GetName()] = label.GetValue()
			}

			var value float64
			switch metricType {
			case dto.MetricType_COUNTER:
				value = metricLabel.Counter.GetValue()
			case dto.MetricType_GAUGE:
				value = metricLabel.GetGauge().GetValue()
			case dto.MetricType_UNTYPED:
				value = metricLabel.GetUntyped().GetValue()
			case dto.MetricType_SUMMARY:
				value = metricLabel.GetSummary().GetSampleSum()
			case dto.MetricType_HISTOGRAM:
				value = metricLabel.GetHistogram().GetSampleSum()
			default:
				continue
			}

			metric := &models.Metric{
				Name:   metricName,
				Labels: labels,
				Value:  value,
			}
			result = append(result, metric)
		}
	}

	return result, nil
}
