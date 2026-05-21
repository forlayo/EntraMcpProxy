# Audit Sink Wiring — Reference Examples

EntraMcpProxy emits structured JSON audit events via the standard .NET `ILogger`
infrastructure using the `EntraMcpProxy.Audit` category. All audit events carry
a `log_category` field set to `EntraMcpProxy.Audit`.

Operators choose one of the sinks below based on their organisation's logging stack.
These examples are reference configurations — mix and match as needed.

---

## 1. Azure Monitor / Application Insights

Use Application Insights to ship audit events to Azure Monitor. Events appear in
`traces` and are queryable via KQL.

**NuGet package (add to `EntraMcpProxy.csproj`):**

```xml
<PackageReference Include="Microsoft.Extensions.Logging.ApplicationInsights" Version="2.22.0" />
```

**appsettings.json / environment variables:**

```json
{
  "ApplicationInsights": {
    "ConnectionString": "<your-connection-string>"
  },
  "Logging": {
    "ApplicationInsights": {
      "LogLevel": {
        "Default": "Warning",
        "EntraMcpProxy.Audit": "Information"
      }
    }
  }
}
```

Or via environment variables (recommended for containers):

```bash
APPLICATIONINSIGHTS__CONNECTIONSTRING="InstrumentationKey=...;IngestionEndpoint=..."
Logging__ApplicationInsights__LogLevel__EntraMcpProxy.Audit=Information
```

**Program.cs wiring:**

```csharp
builder.Services.AddApplicationInsightsTelemetry();
builder.Logging.AddApplicationInsights();
```

**KQL query example (Azure Log Analytics):**

```kql
traces
| where customDimensions.log_category == "EntraMcpProxy.Audit"
| project timestamp, message, customDimensions
| order by timestamp desc
```

---

## 2. OpenTelemetry → SIEM (Splunk / Datadog / Elastic)

EntraMcpProxy ships OpenTelemetry tracing out of the box (Block B). To ship
logs to a SIEM via an OTel collector, add the OpenTelemetry Logs exporter:

**NuGet packages:**

```xml
<PackageReference Include="OpenTelemetry.Extensions.Hosting" Version="1.15.3" />
<PackageReference Include="OpenTelemetry.Exporter.OpenTelemetryProtocol" Version="1.15.3" />
```

**Program.cs wiring (extend the existing OTel setup):**

```csharp
builder.Services.AddOpenTelemetry()
    .ConfigureResource(r => r.AddService("entra-mcp-proxy", serviceVersion: "1.0"))
    .WithTracing(tracing => tracing
        .AddAspNetCoreInstrumentation()
        .AddHttpClientInstrumentation()
        .AddSource("EntraMcpProxy")
        .AddOtlpExporter())
    .WithLogging(logging => logging
        .AddOtlpExporter());  // <-- add this
```

**Environment variables (point at your OTel collector):**

```bash
OTEL_EXPORTER_OTLP_ENDPOINT=http://otel-collector:4317
OTEL_EXPORTER_OTLP_PROTOCOL=grpc
```

**OTel Collector config snippet (collector → Splunk HEC):**

```yaml
exporters:
  splunk_hec:
    token: "<splunk-hec-token>"
    endpoint: "https://splunk.example.com:8088/services/collector"
    index: "entra_mcp_proxy"

service:
  pipelines:
    logs:
      receivers: [otlp]
      processors: [batch]
      exporters: [splunk_hec]
```

**Filtering to audit events only** (in the collector processor):

```yaml
processors:
  filter/audit_only:
    logs:
      include:
        match_type: strict
        record_attributes:
          - key: log.category
            value: "EntraMcpProxy.Audit"
```

---

## 3. File Sink — Kubernetes Sidecar Pattern

Write audit events to a file, then let a log-shipper sidecar (Fluent Bit,
Promtail, Filebeat) pick them up from a shared volume.

**NuGet package:**

```xml
<PackageReference Include="Serilog.Extensions.Hosting" Version="8.0.0" />
<PackageReference Include="Serilog.Sinks.File" Version="6.0.0" />
<PackageReference Include="Serilog.Formatting.Compact" Version="3.0.0" />
```

**Program.cs — configure Serilog before `WebApplication.CreateBuilder`:**

```csharp
Log.Logger = new LoggerConfiguration()
    .MinimumLevel.Override("Microsoft", LogEventLevel.Warning)
    .Filter.ByIncludingOnly(logEvent =>
    {
        if (logEvent.Properties.TryGetValue("SourceContext", out var src))
            return src.ToString().Contains("EntraMcpProxy.Audit");
        return false;
    })
    .WriteTo.File(
        formatter: new CompactJsonFormatter(),
        path: "/var/log/entra-mcp-proxy/audit-.jsonl",
        rollingInterval: RollingInterval.Day,
        retainedFileCountLimit: 30,
        shared: true)
    .CreateLogger();

builder.Host.UseSerilog();
```

**Kubernetes Pod spec (abbreviated):**

```yaml
containers:
  - name: entra-mcp-proxy
    image: <your-registry>/entra-mcp-proxy:latest
    volumeMounts:
      - name: audit-logs
        mountPath: /var/log/entra-mcp-proxy

  - name: log-shipper
    image: fluent/fluent-bit:3.2
    volumeMounts:
      - name: audit-logs
        mountPath: /var/log/entra-mcp-proxy
        readOnly: true
    # Fluent Bit config: tail /var/log/entra-mcp-proxy/audit-*.jsonl, ship to Loki/S3/etc.

volumes:
  - name: audit-logs
    emptyDir: {}
```

---

## Choosing a Sink

| Scenario | Recommended sink |
|---|---|
| Azure-native org with App Insights already deployed | Option 1 (Application Insights) |
| Existing OTel collector infrastructure (Datadog, Splunk, Elastic) | Option 2 (OTel OTLP exporter) |
| Kubernetes + Fluent Bit / Promtail already scraping pod logs | Option 3 (File sink + sidecar) |
| No existing log infrastructure, just need local dev visibility | Built-in `console` provider (no extra config) |

All options preserve the `EntraMcpProxy.Audit` category and the structured JSON
fields emitted by `AuditLog.cs`. See `/Infrastructure/AuditLog.cs` for the full
list of audit event types and their fields.
