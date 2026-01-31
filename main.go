package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/prometheus/client_golang/prometheus/promhttp"

	// Zipkin imports
	"github.com/openzipkin/zipkin-go"
	zipkinhttp "github.com/openzipkin/zipkin-go/reporter/http"
	"github.com/openzipkin/zipkin-go/model"
)

type CurrencyRate struct {
	From string  `json:"from"`
	To   string  `json:"to"`
	Rate float64 `json:"rate"`
}

// Global variables for tracing
var (
	tracer *zipkin.Tracer
)

// Метрики Prometheus
var (
	httpRequestsTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "muffin_currency_requests_total",
			Help: "Total number of HTTP requests",
		},
		[]string{"method", "path", "status", "trace_id"},
	)

	httpRequestDuration = promauto.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "muffin_currency_request_duration_seconds",
			Help:    "HTTP request duration",
			Buckets: prometheus.DefBuckets,
		},
		[]string{"method", "path", "trace_id"},
	)

	currencyRateGauge = promauto.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "muffin_currency_rate",
			Help: "Current currency exchange rate",
		},
		[]string{"from", "to", "trace_id"},
	)

	// Health метрика
	healthStatus = promauto.NewGauge(
		prometheus.GaugeOpts{
			Name: "muffin_currency_health",
			Help: "Health status (1 = healthy)",
		},
	)
)

// Хранилище курсов
var rates = map[string]map[string]float64{
	"CARAMEL":   {"CHOKOLATE": 0.85, "PLAIN": 75.50, "CARAMEL": 1},
	"CHOKOLATE": {"CARAMEL": 1.18, "PLAIN": 89.00, "CHOKOLATE": 1},
	"PLAIN":     {"CHOKOLATE": 0.013, "CARAMEL": 0.011, "PLAIN": 1},
}

// Initialize Zipkin tracing
func initTracing(serviceName, zipkinURL string) error {
	// Create a reporter to send traces to Zipkin
	reporter := zipkinhttp.NewReporter(zipkinURL)
	
	// Create local endpoint
	endpoint, err := zipkin.NewEndpoint(serviceName, "localhost:8080")
	if err != nil {
		return fmt.Errorf("failed to create zipkin endpoint: %w", err)
	}
	
	// Create the tracer
	tracer, err = zipkin.NewTracer(
		reporter,
		zipkin.WithLocalEndpoint(endpoint),
		zipkin.WithTraceID128Bit(true), // For compatibility with Spring Boot 3
		zipkin.WithSharedSpans(false),
		zipkin.WithSampler(zipkin.AlwaysSample),
	)
	
	if err != nil {
		return fmt.Errorf("failed to create zipkin tracer: %w", err)
	}
	
	slog.Info("Zipkin tracing initialized", 
		"service", serviceName, 
		"zipkin_url", zipkinURL)
	
	return nil
}

// Zipkin tracing middleware
func tracingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Start a new span for this request
		span := tracer.StartSpan(r.URL.Path, 
			zipkin.Kind(model.Server),
			zipkin.RemoteEndpoint(nil),
		)
		defer span.Finish()
		
		// Add span to context
		ctx := zipkin.NewContext(r.Context(), span)
		
		// Add HTTP tags to span
		span.Tag("http.method", r.Method)
		span.Tag("http.url", r.URL.String())
		span.Tag("http.path", r.URL.Path)
		span.Tag("component", "http")
		
		// Get trace ID for logging and metrics
		traceID := span.Context().TraceID.String()
		
		// Add trace ID to response headers
		w.Header().Set("X-Trace-ID", traceID)
		
		// Create custom response writer to capture status code
		rw := &responseWriter{
			ResponseWriter: w,
			statusCode:     http.StatusOK,
			traceID:        traceID,
		}
		
		// Log request start with trace ID
		slog.Info("Request started",
			"method", r.Method,
			"path", r.URL.Path,
			"trace_id", traceID,
			"span_id", span.Context().ID.String(),
		)
		
		// Call next handler
		next.ServeHTTP(rw, r.WithContext(ctx))
		
		// Add status code to span
		span.Tag("http.status_code", fmt.Sprintf("%d", rw.statusCode))
		if rw.statusCode >= 400 {
			span.Tag("error", "true")
		}
		
		// Log request completion
		slog.Info("Request completed",
			"method", r.Method,
			"path", r.URL.Path,
			"status", rw.statusCode,
			"trace_id", traceID,
		)
	})
}

// Updated metrics middleware with tracing
func metricsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		
		// Get trace ID from context
		var traceID string
		if span := zipkin.SpanFromContext(r.Context()); span != nil {
			traceID = span.Context().TraceID.String()
		}
		
		// Wrap response writer
		rw := &responseWriter{
			ResponseWriter: w,
			statusCode:     http.StatusOK,
			traceID:        traceID,
		}
		
		next.ServeHTTP(rw, r)
		
		duration := time.Since(start).Seconds()
		
		// Record metrics with trace ID
		httpRequestsTotal.WithLabelValues(
			r.Method,
			r.URL.Path,
			fmt.Sprintf("%d", rw.statusCode),
			traceID,
		).Inc()
		
		httpRequestDuration.WithLabelValues(
			r.Method,
			r.URL.Path,
			traceID,
		).Observe(duration)
	})
}

// Extended response writer
type responseWriter struct {
	http.ResponseWriter
	statusCode int
	traceID    string
}

func (rw *responseWriter) WriteHeader(code int) {
	rw.statusCode = code
	rw.ResponseWriter.WriteHeader(code)
}

// Handler для /rate с трейсингом
func getRateHandler(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	span := zipkin.SpanFromContext(ctx)
	var traceID string
	
	if span != nil {
		traceID = span.Context().TraceID.String()
		span.Tag("handler", "get_rate")
		span.Tag("operation", "currency_conversion")
	}
	
	from := r.URL.Query().Get("from")
	to := r.URL.Query().Get("to")
	
	// Log with trace ID
	slog.Info("Processing currency conversion",
		"from", from,
		"to", to,
		"trace_id", traceID,
	)
	
	if from == "" || to == "" {
		slog.Error("Missing parameters", 
			"from", from, 
			"to", to,
			"trace_id", traceID)
		
		if span != nil {
			span.Tag("error", "missing_parameters")
		}
		
		http.Error(w, `{"error": "Missing 'from' or 'to' parameter"}`, http.StatusBadRequest)
		return
	}
	
	rate, exists := rates[from][to]
	if !exists {
		slog.Error("Currency pair not found",
			"from", from,
			"to", to,
			"trace_id", traceID)
		
		if span != nil {
			span.Tag("error", "pair_not_found")
		}
		
		http.Error(w, `{"error": "Currency pair not found"}`, http.StatusNotFound)
		return
	}
	
	// Add currency pair tags to span
	if span != nil {
		span.Tag("currency.from", from)
		span.Tag("currency.to", to)
		span.Tag("currency.rate", fmt.Sprintf("%f", rate))
	}
	
	// Export to Prometheus with trace ID
	currencyRateGauge.WithLabelValues(from, to, traceID).Set(rate)
	
	response := CurrencyRate{
		From: from,
		To:   to,
		Rate: rate,
	}
	
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
	
	slog.Info("Currency rate returned",
		"from", from,
		"to", to,
		"rate", rate,
		"trace_id", traceID,
	)
}

// Health check handler with tracing
func healthHandler(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	span := zipkin.SpanFromContext(ctx)
	var traceID string
	
	if span != nil {
		traceID = span.Context().TraceID.String()
		span.Tag("handler", "health_check")
	}
	
	healthStatus.Set(1)
	
	slog.Info("Health check requested", "trace_id", traceID)
	
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{
		"status":    "healthy",
		"timestamp": time.Now().Format(time.RFC3339),
		"trace_id":  traceID,
	})
}

// Readiness probe with tracing
func readyHandler(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	span := zipkin.SpanFromContext(ctx)
	var traceID string
	
	if span != nil {
		traceID = span.Context().TraceID.String()
		span.Tag("handler", "readiness_check")
	}
	
	slog.Info("Readiness check requested", "trace_id", traceID)
	
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{
		"status":    "ready",
		"timestamp": time.Now().Format(time.RFC3339),
		"trace_id":  traceID,
	})
}

func main() {
	// Настройка structured logging
	logFile, err := os.OpenFile("logs/app.log", os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0666)
	if err != nil {
		slog.Error("Failed to open log file", "error", err)
		os.Exit(1)
	}
	defer logFile.Close()
	
	// Создаем multi-writer для логирования в файл и stdout
	multiWriter := io.MultiWriter(os.Stdout, logFile)
	logger := slog.New(slog.NewJSONHandler(multiWriter, &slog.HandlerOptions{
		Level: slog.LevelInfo,
	}))
	slog.SetDefault(logger)
	
	// Инициализируем Zipkin tracing
	err = initTracing("muffin-currency", "http://localhost:9411/api/v2/spans")
	if err != nil {
		slog.Error("Failed to initialize Zipkin tracing", "error", err)
		os.Exit(1)
	}
	
	// Инициализируем health метрику
	healthStatus.Set(1)
	
	// Настройка маршрутов
	mux := http.NewServeMux()
	
	// Business логика
	mux.HandleFunc("/rate", getRateHandler)
	
	// Health checks
	mux.HandleFunc("/healthz", healthHandler)
	mux.HandleFunc("/readyz", readyHandler)
	
	// Prometheus метрики
	mux.Handle("/metrics", promhttp.Handler())
	
	// Apply middlewares in order: tracing -> metrics -> router
	handler := tracingMiddleware(mux)
	handler = metricsMiddleware(handler)
	
	// Конфигурируем порт
	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}
	
	server := &http.Server{
		Addr:         ":" + port,
		Handler:      handler,
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 15 * time.Second,
		IdleTimeout:  60 * time.Second,
	}
	
	// Graceful shutdown
	go func() {
		sigChan := make(chan os.Signal, 1)
		signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)
		<-sigChan
		
		logger.Info("Shutting down server...")
		healthStatus.Set(0)
		
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		
		if err = server.Shutdown(ctx); err != nil {
			logger.Error("Server forced to shutdown", "error", err)
		}
	}()
	
	logger.Info("Starting server", 
		"port", port,
		"zipkin_endpoint", "http://localhost:9411/api/v2/spans")
	
	if err = server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		logger.Error("Server failed to start", "error", err)
		os.Exit(1)
	}
}
