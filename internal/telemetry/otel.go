package telemetry

import (
	"context"
	"fmt"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	semconv "go.opentelemetry.io/otel/semconv/v1.17.0"
	"go.opentelemetry.io/otel/trace"
)

// InitProvider initializes the OpenTelemetry tracer provider.
func InitProvider(ctx context.Context, defaultServiceName string) (*sdktrace.TracerProvider, error) {
	// Setup exporter (OTLP HTTP default to localhost:4318)
	exporter, err := otlptracehttp.New(ctx, otlptracehttp.WithInsecure())
	if err != nil {
		return nil, fmt.Errorf("failed to create OTLP trace exporter: %w", err)
	}

	// Define resource attributes (service name)
	res, err := resource.New(ctx,
		resource.WithAttributes(
			semconv.ServiceName(defaultServiceName),
			semconv.TelemetrySDKLanguageGo,
		),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create resource: %w", err)
	}

	// Setup TracerProvider
	tp := sdktrace.NewTracerProvider(
		sdktrace.WithBatcher(exporter),
		sdktrace.WithResource(res),
	)

	// Set global provider
	otel.SetTracerProvider(tp)
	
	// Create a fast-path tracer instance
	_ = otel.Tracer("ads-httpproxy/internal/proxy")

	return tp, nil
}

// GetTracer returns a globally configured tracer instance
func GetTracer(name string) trace.Tracer {
	return otel.Tracer(name)
}
