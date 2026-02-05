package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/exporters/otlp/otlpmetric/otlpmetricgrpc"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracegrpc"
	"go.opentelemetry.io/otel/metric"
	"go.opentelemetry.io/otel/propagation"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	semconv "go.opentelemetry.io/otel/semconv/v1.21.0"
	"go.opentelemetry.io/otel/trace"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

// Курсы валют
var rates = map[string]map[string]float64{
	"CARAMEL":   {"CHOKOLATE": 0.85, "PLAIN": 75.50, "CARAMEL": 1},
	"CHOKOLATE": {"CARAMEL": 1.18, "PLAIN": 89.00, "CHOKOLATE": 1},
	"PLAIN":     {"CHOKOLATE": 0.013, "CARAMEL": 0.011, "PLAIN": 1},
}

// CurrencyRate - структура ответа
type CurrencyRate struct {
	From string  `json:"from"`
	To   string  `json:"to"`
	Rate float64 `json:"rate"`
}

// ErrorResponse - структура ошибки
type ErrorResponse struct {
	Error   string `json:"error"`
	Code    int    `json:"code"`
	Message string `json:"message"`
}

// Глобальные переменные для телеметрии
var (
	tracer         trace.Tracer
	meter          metric.Meter
	requestCounter metric.Int64Counter
	requestLatency metric.Float64Histogram
)

// Config - конфигурация приложения
type Config struct {
	ServiceName    string
	ServiceVersion string
	OTELEndpoint   string
	HTTPPort       string
}

func getConfig() Config {
	return Config{
		ServiceName:    getEnv("SERVICE_NAME", "muffin-currency"),
		ServiceVersion: getEnv("SERVICE_VERSION", "1.0.0"),
		OTELEndpoint:   getEnv("OTEL_EXPORTER_OTLP_ENDPOINT", "localhost:4317"),
		HTTPPort:       getEnv("HTTP_PORT", "8080"),
	}
}

func getEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

// initResource создает ресурс с информацией о сервисе
func initResource(cfg Config) (*resource.Resource, error) {
	return resource.Merge(
		resource.Default(),
		resource.NewWithAttributes(
			semconv.SchemaURL,
			semconv.ServiceName(cfg.ServiceName),
			semconv.ServiceVersion(cfg.ServiceVersion),
			attribute.String("environment", getEnv("ENVIRONMENT", "development")),
		),
	)
}

// initTracerProvider инициализирует провайдер трейсинга
func initTracerProvider(ctx context.Context, res *resource.Resource, cfg Config) (*sdktrace.TracerProvider, error) {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	conn, err := grpc.DialContext(ctx, cfg.OTELEndpoint,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithBlock(),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create gRPC connection: %w", err)
	}

	exporter, err := otlptracegrpc.New(ctx, otlptracegrpc.WithGRPCConn(conn))
	if err != nil {
		return nil, fmt.Errorf("failed to create trace exporter: %w", err)
	}

	tp := sdktrace.NewTracerProvider(
		sdktrace.WithBatcher(exporter),
		sdktrace.WithResource(res),
		sdktrace.WithSampler(sdktrace.AlwaysSample()),
	)

	otel.SetTracerProvider(tp)

	// Устанавливаем propagator для распространения контекста трейса
	otel.SetTextMapPropagator(propagation.NewCompositeTextMapPropagator(
		propagation.TraceContext{},
		propagation.Baggage{},
	))

	return tp, nil
}

// initMeterProvider инициализирует провайдер метрик
func initMeterProvider(ctx context.Context, res *resource.Resource, cfg Config) (*sdkmetric.MeterProvider, error) {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	conn, err := grpc.DialContext(ctx, cfg.OTELEndpoint,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithBlock(),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create gRPC connection: %w", err)
	}

	exporter, err := otlpmetricgrpc.New(ctx, otlpmetricgrpc.WithGRPCConn(conn))
	if err != nil {
		return nil, fmt.Errorf("failed to create metric exporter: %w", err)
	}

	mp := sdkmetric.NewMeterProvider(
		sdkmetric.WithReader(sdkmetric.NewPeriodicReader(exporter, sdkmetric.WithInterval(10*time.Second))),
		sdkmetric.WithResource(res),
	)

	otel.SetMeterProvider(mp)
	return mp, nil
}

// initMetrics инициализирует метрики
func initMetrics(cfg Config) error {
	meter = otel.Meter(cfg.ServiceName)

	var err error

	// Счетчик запросов
	requestCounter, err = meter.Int64Counter(
		"http_requests_total",
		metric.WithDescription("Total number of HTTP requests"),
		metric.WithUnit("{request}"),
	)
	if err != nil {
		return fmt.Errorf("failed to create request counter: %w", err)
	}

	// Гистограмма латентности
	requestLatency, err = meter.Float64Histogram(
		"http_request_duration_seconds",
		metric.WithDescription("HTTP request latency in seconds"),
		metric.WithUnit("s"),
	)
	if err != nil {
		return fmt.Errorf("failed to create latency histogram: %w", err)
	}

	// Gauge для курсов валют
	_, err = meter.Float64ObservableGauge(
		"currency_rate",
		metric.WithDescription("Current currency exchange rate"),
		metric.WithFloat64Callback(func(ctx context.Context, observer metric.Float64Observer) error {
			for from, toRates := range rates {
				for to, rate := range toRates {
					observer.Observe(rate,
						metric.WithAttributes(
							attribute.String("from", from),
							attribute.String("to", to),
						),
					)
				}
			}
			return nil
		}),
	)
	if err != nil {
		return fmt.Errorf("failed to create rate gauge: %w", err)
	}

	return nil
}

// RateHandler обрабатывает запросы курсов валют
type RateHandler struct {
	tracer trace.Tracer
}

func NewRateHandler(tracer trace.Tracer) *RateHandler {
	return &RateHandler{tracer: tracer}
}

func (h *RateHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	start := time.Now()

	// Получаем текущий span из контекста (создан otelhttp middleware)
	span := trace.SpanFromContext(ctx)

	// Получаем query параметры
	from := r.URL.Query().Get("from")
	to := r.URL.Query().Get("to")

	// Добавляем атрибуты к span
	span.SetAttributes(
		attribute.String("currency.from", from),
		attribute.String("currency.to", to),
		attribute.String("http.method", r.Method),
		attribute.String("http.url", r.URL.String()),
	)

	// Валидация параметров
	if from == "" || to == "" {
		h.handleError(ctx, w, span, start, from, to, http.StatusBadRequest, "missing required parameters 'from' and 'to'")
		return
	}

	// Создаем дочерний span для поиска курса
	ctx, lookupSpan := h.tracer.Start(ctx, "lookup_rate",
		trace.WithAttributes(
			attribute.String("currency.from", from),
			attribute.String("currency.to", to),
		),
	)

	// Ищем курс
	rate, found := h.lookupRate(from, to)
	lookupSpan.End()

	if !found {
		h.handleError(ctx, w, span, start, from, to, http.StatusNotFound, fmt.Sprintf("rate not found for %s -> %s", from, to))
		return
	}

	// Формируем ответ
	response := CurrencyRate{
		From: from,
		To:   to,
		Rate: rate,
	}

	// Добавляем результат в span
	span.SetAttributes(
		attribute.Float64("currency.rate", rate),
		attribute.Int("http.status_code", http.StatusOK),
	)

	// Записываем метрики
	h.recordMetrics(ctx, start, http.StatusOK, from, to)

	// Отправляем ответ
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(response)
}

func (h *RateHandler) lookupRate(from, to string) (float64, bool) {
	fromRates, ok := rates[from]
	if !ok {
		return 0, false
	}
	rate, ok := fromRates[to]
	return rate, ok
}

func (h *RateHandler) handleError(ctx context.Context, w http.ResponseWriter, span trace.Span, start time.Time, from, to string, statusCode int, message string) {
	span.SetAttributes(
		attribute.Int("http.status_code", statusCode),
		attribute.String("error.message", message),
	)
	span.RecordError(fmt.Errorf(message))

	// Записываем метрики
	h.recordMetrics(ctx, start, statusCode, from, to)

	// Отправляем ответ
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	json.NewEncoder(w).Encode(ErrorResponse{
		Error:   http.StatusText(statusCode),
		Code:    statusCode,
		Message: message,
	})
}

func (h *RateHandler) recordMetrics(ctx context.Context, start time.Time, statusCode int, from, to string) {
	duration := time.Since(start).Seconds()
	attrs := []attribute.KeyValue{
		attribute.String("method", "GET"),
		attribute.String("path", "/rate"),
		attribute.Int("status", statusCode),
		attribute.String("from", from),
		attribute.String("to", to),
	}
	requestCounter.Add(ctx, 1, metric.WithAttributes(attrs...))
	requestLatency.Record(ctx, duration, metric.WithAttributes(attrs...))
}

// HealthHandler для проверки здоровья сервиса
func HealthHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{
		"status": "healthy",
		"time":   time.Now().UTC().Format(time.RFC3339),
	})
}

func main() {
	cfg := getConfig()
	ctx := context.Background()

	log.Printf("Starting %s v%s", cfg.ServiceName, cfg.ServiceVersion)
	log.Printf("OTEL Endpoint: %s", cfg.OTELEndpoint)

	// Инициализация ресурса
	res, err := initResource(cfg)
	if err != nil {
		log.Fatalf("Failed to create resource: %v", err)
	}

	// Инициализация трейсинга
	tp, err := initTracerProvider(ctx, res, cfg)
	if err != nil {
		log.Printf("Warning: Failed to initialize tracer provider: %v", err)
		log.Println("Continuing without tracing...")
	} else {
		defer func() {
			shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			if err := tp.Shutdown(shutdownCtx); err != nil {
				log.Printf("Error shutting down tracer provider: %v", err)
			}
		}()
	}

	// Инициализация метрик
	mp, err := initMeterProvider(ctx, res, cfg)
	if err != nil {
		log.Printf("Warning: Failed to initialize meter provider: %v", err)
		log.Println("Continuing without metrics...")
	} else {
		defer func() {
			shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			if err := mp.Shutdown(shutdownCtx); err != nil {
				log.Printf("Error shutting down meter provider: %v", err)
			}
		}()
	}

	// Инициализация кастомных метрик
	if err := initMetrics(cfg); err != nil {
		log.Printf("Warning: Failed to initialize metrics: %v", err)
	}

	// Создаем tracer
	tracer = otel.Tracer(cfg.ServiceName)

	// Создаем роутер
	mux := http.NewServeMux()

	// Регистрируем handlers с otelhttp middleware
	rateHandler := NewRateHandler(tracer)
	mux.Handle("/rate", otelhttp.NewHandler(rateHandler, "rate"))
	mux.HandleFunc("/health", HealthHandler)

	// Создаем сервер
	server := &http.Server{
		Addr:         ":" + cfg.HTTPPort,
		Handler:      mux,
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 15 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	// Graceful shutdown
	go func() {
		sigChan := make(chan os.Signal, 1)
		signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
		<-sigChan

		log.Println("Shutting down server...")
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()

		if err := server.Shutdown(shutdownCtx); err != nil {
			log.Printf("Error during server shutdown: %v", err)
		}
	}()

	log.Printf("Server starting on port %s", cfg.HTTPPort)
	if err := server.ListenAndServe(); err != http.ErrServerClosed {
		log.Fatalf("Server error: %v", err)
	}

	log.Println("Server stopped")
}