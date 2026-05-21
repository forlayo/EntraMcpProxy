# SDK Transport Semantics Probe — Result

**Probe date:** 2026-05-21
**SDK:** ModelContextProtocol 0.7.0-preview.1 (and ModelContextProtocol.AspNetCore 0.7.0-preview.1)
**Test file:** `EntraMcpProxy.IntegrationTests/SdkTransportProbeTests.cs`

## Finding

**PER-REQUEST**

The `HttpClientTransport` in ModelContextProtocol 0.7.0-preview.1 re-invokes the full
`HttpClient` handler chain — including any `DelegatingHandler` in the pipeline — for every
JSON-RPC call it makes over HTTP. When the calling code sets an `AsyncLocal<string?>` value
before issuing a tool call, that value flows through the `await` chain into the
`DelegatingHandler.SendAsync` that runs for that specific request. A different value set for
the next call is independently visible to that call's handler invocation.

There is no session-pinning of the `Authorization` header. The SDK creates a new
`HttpRequestMessage` for every outbound JSON-RPC POST, so the delegating handler has a fresh
opportunity to inject per-request credentials on every call.

## Evidence

Test ran **pass** in ~206 ms. The recorded server-side POST requests were:

```
Recorded 4 server-side POST requests:
  path=/ authorization=<null>
  path=/ authorization=<null>
  path=/ authorization=Bearer alice-token
  path=/ authorization=Bearer bob-token
Authorization values observed: [Bearer alice-token, Bearer bob-token]
RESULT: PER-REQUEST semantics — Authorization is re-attached per HTTP call.
        Phase 8 keeps singleton McpClient per downstream.
```

The first two POSTs (with `<null>` auth) are the `initialize` and `notifications/initialized`
messages sent automatically by `McpClient.CreateAsync` before any `AsyncLocal` token was set.
The third POST — the `tools/list` call issued with `CurrentBearer.Value = "alice-token"` —
received `Bearer alice-token`. The fourth POST — the `tools/call` issued with
`CurrentBearer.Value = "bob-token"` — received `Bearer bob-token`.

Full test suite result: **Total: 11, Passed: 11** (all integration tests pass).

## SDK API Notes

The constructor actually available in this preview version is:

```csharp
HttpClientTransport(HttpClientTransportOptions options,
                    HttpClient httpClient,
                    ILoggerFactory? loggerFactory = null,
                    bool ownsHttpClient = false)
```

The transport uses `AutoDetect` mode by default, which first attempts Streamable HTTP (SSE over
POST). This requires a server that correctly implements the MCP Streamable HTTP protocol.
`FakeDownstreamMcp` (WireMock-based) does not implement SSE; the probe therefore spins up a
minimal in-process ASP.NET Core `TestServer` with `MapMcp()` for a fully conformant counterpart.

A secondary fix was also applied to `FakeDownstreamMcp.TryExtractId`: it now returns `long`
for numeric JSON-RPC IDs (not `string`) so future tests that try to use `FakeDownstreamMcp` with
the SDK transport get correct ID-type round-tripping in responses.

## Phase 8 Decision

Phase 8 will keep a singleton `McpClient` per downstream prefix and rely on
per-request OBO via `IHttpContextAccessor`. The silent SP fallback is removed
unless an explicit `IDiscoveryContext` marker is set. The `DownstreamClientManager`
does **not** need to be rewritten to a per-user lifecycle.
