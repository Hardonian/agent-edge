# OpenTelemetry (OTel) Ingestion & Export

AgentPCAP integrates seamlessly with OpenTelemetry, serving as both an OTLP trace receiver and trace exporter.

## 1. Trace Ingestion (`agentpcap otlp`)

AgentPCAP listens on port `4318` (or custom `--listen`) accepting standard OTLP/HTTP JSON spans at `/v1/traces`:

```bash
agentpcap otlp --listen 127.0.0.1:4318
```

### Semantic Convention Mapping

AgentPCAP maps GenAI semantic conventions directly into its canonical domain:

| OpenTelemetry Attribute | APCAP Event Field |
| :--- | :--- |
| `gen_ai.system` | `protocol = MODEL`, `destination.kind = "model"` |
| `gen_ai.request.model` | `destination.name = model_name` |
| `gen_ai.usage.input_tokens` | `tokens.input_tokens` |
| `gen_ai.usage.output_tokens` | `tokens.output_tokens` |
| `span.kind` | Correlated parent-child DAG relations |
| `status.code == 2` | `status = ERROR` |

---

## 2. Trace Export (`agentpcap export otlp`)

Any captured `.apcap` file can be exported back to standard OTLP JSON format for ingestion into Jaeger, Prometheus, or Grafana:

```bash
agentpcap export otlp capture.apcap > traces.json
```
