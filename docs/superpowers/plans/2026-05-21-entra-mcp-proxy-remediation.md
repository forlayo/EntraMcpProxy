# EntraMcpProxy Security Remediation Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Remediate every finding from `audit/2026-05-21-security-review.md` (commit `66abe7bc7cf8243a623d7da5b08bc4b351559d6a`) — both passes — and stand up unit, integration, and Docker-based end-to-end test coverage so the proxy is safe to deploy in front of corporate Entra identities at DisplayNote.

**Architecture:** Solution is split into four projects: the existing `EntraMcpProxy` (app), plus new `EntraMcpProxy.Tests` (unit), `EntraMcpProxy.IntegrationTests` (in-process WebApplicationFactory + WireMock.Net), and `EntraMcpProxy.E2ETests` (Testcontainers running the real container against WireMock containers). All HTTP outbound becomes `IHttpClientFactory`-managed. Configuration moves to strong-typed `IOptions<T>` with `IValidateOptions<T>` enforced at startup. Identity flow is fixed by (a) replacing the hash-based OBO cache key with `oid|tid|scope` from validated claims, and (b) eliminating the silent SP fallback and pinning `Authorization` per-call on each downstream HTTP request — exact downstream-client shape depends on the Phase 2 SDK probe.

**Tech Stack:**
- App: .NET 10, ASP.NET Core, `ModelContextProtocol` SDK (pin exact version once GA; preview only while waiting)
- Tests: xUnit, FluentAssertions, NSubstitute, WireMock.Net, Microsoft.AspNetCore.Mvc.Testing, Testcontainers
- CI: GitHub Actions (lint, build, unit, integration, E2E, vulnerability scan, SBOM)
- Runtime: Docker (pinned digest), k8s ingress in front
- Logging: `Microsoft.Extensions.Logging` + dedicated audit logger category `EntraMcpProxy.Audit` with JSON formatter

**Finding-to-phase map (auditable coverage):**

| Phase | Findings addressed |
|-------|---------------------|
| 0 | N8, N9, N10 (supply chain) |
| 1 | Test scaffolding (enables TDD on every later phase) |
| 2 | Dynamic SDK transport probe — informs Phase 8 |
| 3 | M11, N1, N18, L18 (config + dev-prod separation) |
| 4 | H5, L20 (forwarded headers / PublicBaseUrl) |
| 5 | H3, H4, M8, M9, M10, M12, M13 (OAuth facade) |
| 6 | N13, N14, L17 (JWT explicit validation) |
| 7 | C1, M14, N2 (OBO cache) |
| 8 | C2, H6, N3 (downstream client + SP fallback) |
| 9 | N5, N6, N7, M15 (tool poisoning defense) |
| 10 | N11, N12 (tool result poisoning + size budget) |
| 11 | N4, N21 (per-tool authorization) |
| 12 | N16, N17 (audit + telemetry) |
| 13 | N19, N20 (egress allowlist + governance) |
| 14 | H7 (exception filtering) |
| 15 | E2E test suite (Docker-based) |
| 16 | N1, L20, M12 (documentation) |
| 17 | Final verification gate |

Findings explicitly N/A:
- L16, L19 (already clean; no work needed)
- MCP05 (proxy does not execute commands)

---

## File Structure

**New files**
- `Directory.Packages.props` — central NuGet version pinning
- `EntraMcpProxy.sln` — updated to include test projects
- `Configuration/EntraIdOptions.cs` — strong-typed JWT auth config + validator
- `Configuration/ProxyOptions.cs` — strong-typed proxy options (PublicBaseUrl, refresh interval, allowed redirect URIs, rate limits, downstream egress allowlist)
- `Configuration/DownstreamServerOptions.cs` — replaces `DownstreamServerConfig` with validator
- `Configuration/AuthorizationPolicyOptions.cs` — per-tool authz config
- `Auth/OboCacheKey.cs` — claim-derived cache key record
- `Auth/EntraIdOBOHandler.cs` — rewritten cache + fallback semantics
- `Auth/PkceValidator.cs` — request-level PKCE presence check
- `Auth/RedirectUriValidator.cs` — allowlist check
- `Auth/DownstreamAuthorizationFilter.cs` — per-tool authorization
- `Services/DownstreamClientManager.cs` — rewritten per Phase 2 finding
- `Services/ToolRegistry.cs` — strict prefix check + change-set diffing
- `Services/ToolPolicyService.cs` — tool description/schema sanitization
- `Services/ProxyToolHandler.cs` — provenance wrapping + size budget
- `Services/ToolAggregatorService.cs` — diff/audit on refresh
- `Infrastructure/PublicBaseUrlAccessor.cs` — derives baseUrl from config, not headers
- `Infrastructure/AuditLog.cs` — structured audit emitter
- `Infrastructure/EgressAllowlist.cs` — downstream host validator
- `Infrastructure/GlobalExceptionHandler.cs` — rewritten to never leak Entra body
- `Program.cs` — refactored bootstrap
- `appsettings.json` — placeholders only, no secrets, references env vars
- `Dockerfile` — base image pinned by digest
- `docker-compose.e2e.yml` — proxy + WireMock-Entra + WireMock-downstream + test runner
- `.github/workflows/ci.yml`
- `EntraMcpProxy.Tests/` — unit test project (xUnit + FluentAssertions + NSubstitute)
- `EntraMcpProxy.IntegrationTests/` — WebApplicationFactory + WireMock.Net
- `EntraMcpProxy.E2ETests/` — Testcontainers-driven
- `docs/threat-model.md` — short threat model documenting residual risks
- `docs/operations.md` — deployment / governance checklist

**Modified files** (in addition to above): `README.md`, `EntraMcpProxy.csproj`, `.gitignore`, `appsettings.Development.json`.

**Deleted files**: `Configuration/DownstreamServerConfig.cs` (replaced).

Each file has one clear responsibility. Tests live next to the responsibility they verify, in mirrored namespace under the test project.

---

## Conventions (apply to every task)

- **TDD order**: write the failing test, run it red, write minimal code, run it green, commit.
- **Commits are atomic**: one task = one (or two) commits. Never lump phases.
- **Naming**: test class = `<TypeUnderTest>Tests`, test method = `<MethodOrScenario>_<Condition>_<Expectation>`.
- **Test isolation**: every integration test uses a fresh WireMock instance and a unique tenant GUID seeded per-test to detect cross-test leakage.
- **No secrets in any file under source control.** Tests use deterministic test-only key material generated at test-class init.
- **`dotnet format` clean before commit.**
- **Each commit message** ends with `Refs: <finding-id(s)>` (e.g. `Refs: C1, M14`) for audit traceability.

---

# Phase 0 — Project Hygiene & Supply-Chain Hardening

**Goal:** Get supply-chain controls in place before writing or changing any code. **Refs: N8, N9, N10.**

### Task 0.1: Central package version management

**Files:**
- Create: `Directory.Packages.props`
- Modify: `EntraMcpProxy.csproj`

- [ ] **Step 1: Create `Directory.Packages.props`**

```xml
<Project>
  <PropertyGroup>
    <ManagePackageVersionsCentrally>true</ManagePackageVersionsCentrally>
    <CentralPackageTransitivePinningEnabled>true</CentralPackageTransitivePinningEnabled>
  </PropertyGroup>
  <ItemGroup>
    <!-- App -->
    <PackageVersion Include="Microsoft.AspNetCore.Authentication.JwtBearer" Version="10.0.0" />
    <PackageVersion Include="Azure.Identity" Version="1.13.1" />
    <PackageVersion Include="ModelContextProtocol" Version="0.7.0-preview.1" />
    <PackageVersion Include="ModelContextProtocol.AspNetCore" Version="0.7.0-preview.1" />
    <!-- Tests -->
    <PackageVersion Include="Microsoft.NET.Test.Sdk" Version="17.11.1" />
    <PackageVersion Include="xunit" Version="2.9.2" />
    <PackageVersion Include="xunit.runner.visualstudio" Version="2.8.2" />
    <PackageVersion Include="FluentAssertions" Version="6.12.2" />
    <PackageVersion Include="NSubstitute" Version="5.3.0" />
    <PackageVersion Include="Microsoft.AspNetCore.Mvc.Testing" Version="10.0.0" />
    <PackageVersion Include="WireMock.Net" Version="1.6.7" />
    <PackageVersion Include="Testcontainers" Version="4.0.0" />
    <PackageVersion Include="System.IdentityModel.Tokens.Jwt" Version="8.2.0" />
    <PackageVersion Include="Microsoft.IdentityModel.JsonWebTokens" Version="8.2.0" />
  </ItemGroup>
</Project>
```

- [ ] **Step 2: Strip versions from `EntraMcpProxy.csproj` (now centrally managed) and enable lockfile**

```xml
<Project Sdk="Microsoft.NET.Sdk.Web">
  <PropertyGroup>
    <TargetFramework>net10.0</TargetFramework>
    <RootNamespace>EntraMcpProxy</RootNamespace>
    <ImplicitUsings>enable</ImplicitUsings>
    <Nullable>enable</Nullable>
    <TreatWarningsAsErrors>true</TreatWarningsAsErrors>
    <RestorePackagesWithLockFile>true</RestorePackagesWithLockFile>
    <RestoreLockedMode Condition="'$(ContinuousIntegrationBuild)' == 'true'">true</RestoreLockedMode>
  </PropertyGroup>
  <ItemGroup>
    <PackageReference Include="ModelContextProtocol" />
    <PackageReference Include="ModelContextProtocol.AspNetCore" />
    <PackageReference Include="Microsoft.AspNetCore.Authentication.JwtBearer" />
    <PackageReference Include="Azure.Identity" />
  </ItemGroup>
</Project>
```

- [ ] **Step 3: Restore + commit lockfile**

Run: `dotnet restore`
Verify `packages.lock.json` is created. Commit: `Directory.Packages.props`, `EntraMcpProxy.csproj`, `packages.lock.json`.

Commit message: `chore: pin nuget versions centrally + enable lockfile (Refs: N8)`

### Task 0.2: Pin Docker base image to digest

**Files:** Modify: `Dockerfile`

- [ ] **Step 1: Resolve current digest**

Run: `docker pull mcr.microsoft.com/dotnet/aspnet:10.0 && docker inspect --format='{{index .RepoDigests 0}}' mcr.microsoft.com/dotnet/aspnet:10.0`
Capture the `sha256:...` digest. Repeat for `mcr.microsoft.com/dotnet/sdk:10.0`.

- [ ] **Step 2: Edit `Dockerfile`**

```dockerfile
# Replace floating tags with digests captured in Step 1.
FROM mcr.microsoft.com/dotnet/aspnet:10.0@sha256:<DIGEST> AS base
WORKDIR /app
EXPOSE 80
USER $APP_UID

FROM mcr.microsoft.com/dotnet/sdk:10.0@sha256:<DIGEST> AS build
ARG BUILD_CONFIGURATION=Release
WORKDIR /src
COPY ["Directory.Packages.props", "."]
COPY ["EntraMcpProxy.csproj", "."]
COPY ["packages.lock.json", "."]
RUN dotnet restore "./EntraMcpProxy.csproj" --locked-mode
COPY . .
RUN dotnet build "./EntraMcpProxy.csproj" -c $BUILD_CONFIGURATION -o /app/build --no-restore

FROM build AS publish
ARG BUILD_CONFIGURATION=Release
RUN dotnet publish "./EntraMcpProxy.csproj" -c $BUILD_CONFIGURATION -o /app/publish \
    --no-restore /p:SelfContained=false /p:PublishSingleFile=false /p:UseAppHost=false

FROM base AS final
WORKDIR /app
COPY --from=publish /app/publish .
ENTRYPOINT ["dotnet", "EntraMcpProxy.dll"]
```

- [ ] **Step 3: Build + commit**

Run: `docker build -t entra-mcp-proxy:test .`
Verify it builds.
Commit message: `chore: pin docker base image digests + locked restore (Refs: N9)`

### Task 0.3: GitHub Actions CI

**Files:** Create `.github/workflows/ci.yml`

- [ ] **Step 1: Write workflow**

```yaml
name: CI
on:
  push:
    branches: [main]
  pull_request:
    branches: [main]
permissions:
  contents: read

jobs:
  build-test:
    runs-on: ubuntu-latest
    env:
      ContinuousIntegrationBuild: 'true'
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-dotnet@v4
        with:
          dotnet-version: '10.0.x'
      - run: dotnet restore --locked-mode
      - run: dotnet build --no-restore --configuration Release -warnaserror
      - run: dotnet test --no-build --configuration Release --logger trx --results-directory TestResults
      - name: Vulnerability scan
        run: dotnet list package --vulnerable --include-transitive 2>&1 | tee vuln.txt && ! grep -E '(Critical|High)' vuln.txt
      - uses: actions/upload-artifact@v4
        if: always()
        with:
          name: test-results
          path: TestResults

  e2e:
    runs-on: ubuntu-latest
    needs: build-test
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-dotnet@v4
        with:
          dotnet-version: '10.0.x'
      - run: dotnet restore --locked-mode
      - run: dotnet test EntraMcpProxy.E2ETests --configuration Release --logger trx

  sbom:
    runs-on: ubuntu-latest
    needs: build-test
    steps:
      - uses: actions/checkout@v4
      - uses: anchore/sbom-action@v0
        with:
          path: .
          format: cyclonedx-json
```

- [ ] **Step 2: Commit**

Commit message: `ci: add build/test/scan/sbom workflow (Refs: N10)`

---

# Phase 1 — Test Project Scaffolding

**Goal:** Three test projects exist with one trivial passing test each. Establishes the platform every later TDD step builds on.

### Task 1.1: Unit test project

**Files:** Create `EntraMcpProxy.Tests/EntraMcpProxy.Tests.csproj`, `EntraMcpProxy.Tests/SmokeTest.cs`

- [ ] **Step 1: Create project**

```xml
<Project Sdk="Microsoft.NET.Sdk">
  <PropertyGroup>
    <TargetFramework>net10.0</TargetFramework>
    <Nullable>enable</Nullable>
    <ImplicitUsings>enable</ImplicitUsings>
    <IsPackable>false</IsPackable>
    <RestorePackagesWithLockFile>true</RestorePackagesWithLockFile>
  </PropertyGroup>
  <ItemGroup>
    <PackageReference Include="Microsoft.NET.Test.Sdk" />
    <PackageReference Include="xunit" />
    <PackageReference Include="xunit.runner.visualstudio" />
    <PackageReference Include="FluentAssertions" />
    <PackageReference Include="NSubstitute" />
  </ItemGroup>
  <ItemGroup>
    <ProjectReference Include="..\EntraMcpProxy.csproj" />
  </ItemGroup>
</Project>
```

- [ ] **Step 2: Smoke test**

```csharp
using FluentAssertions;
using Xunit;
namespace EntraMcpProxy.Tests;
public class SmokeTest { [Fact] public void True_is_true() => true.Should().BeTrue(); }
```

- [ ] **Step 3: Add to solution + run**

Run: `dotnet sln add EntraMcpProxy.Tests/EntraMcpProxy.Tests.csproj && dotnet test`
Expected: 1 passed.
Commit: `test: add unit test project scaffolding`

### Task 1.2: Integration test project

**Files:** Create `EntraMcpProxy.IntegrationTests/EntraMcpProxy.IntegrationTests.csproj`, `EntraMcpProxy.IntegrationTests/Fixtures/ProxyAppFactory.cs`

- [ ] **Step 1: Create project (mirror 1.1, add `Microsoft.AspNetCore.Mvc.Testing`, `WireMock.Net`, `System.IdentityModel.Tokens.Jwt`).**

- [ ] **Step 2: WebApplicationFactory fixture**

```csharp
using Microsoft.AspNetCore.Mvc.Testing;
namespace EntraMcpProxy.IntegrationTests.Fixtures;

public class ProxyAppFactory : WebApplicationFactory<Program>
{
    public string EntraMockUrl { get; init; } = "";
    public string DownstreamMockUrl { get; init; } = "";
    public string PublicBaseUrl { get; init; } = "https://proxy.test";
    public string TenantId { get; init; } = Guid.NewGuid().ToString();
    public string ClientId { get; init; } = Guid.NewGuid().ToString();
    public string ClientSecret { get; init; } = "test-secret-not-real";

    protected override void ConfigureWebHost(IWebHostBuilder builder)
    {
        builder.UseEnvironment("IntegrationTest");
        builder.ConfigureAppConfiguration((_, cfg) =>
        {
            cfg.AddInMemoryCollection(new Dictionary<string,string?>
            {
                ["EntraId:Authority"]            = $"{EntraMockUrl}/{TenantId}/v2.0",
                ["EntraId:TenantId"]             = TenantId,
                ["EntraId:ClientId"]             = ClientId,
                ["EntraId:RequireHttpsMetadata"] = "false",
                ["Proxy:PublicBaseUrl"]          = PublicBaseUrl,
                ["Proxy:AllowedRedirectUris:0"]  = "https://claude.ai/api/mcp/auth_callback",
                ["Proxy:EgressAllowlist:0"]      = new Uri(DownstreamMockUrl).Host,
            });
        });
    }
}
```

- [ ] **Step 3: Smoke test**

```csharp
[Fact]
public async Task Healthz_returns_200()
{
    await using var factory = new ProxyAppFactory();
    using var client = factory.CreateClient();
    var resp = await client.GetAsync("/api/healthz");
    resp.StatusCode.Should().Be(HttpStatusCode.OK);
}
```

Run: `dotnet test EntraMcpProxy.IntegrationTests` — expected 1 passed (will require Program.cs to expose `public partial class Program {}` at end — add that line).
Commit: `test: add integration test scaffolding`

### Task 1.3: WireMock helper for fake Entra v2.0 endpoints

**Files:** Create `EntraMcpProxy.IntegrationTests/Fixtures/FakeEntra.cs`

- [ ] **Step 1: Write fixture**

```csharp
using WireMock.RequestBuilders;
using WireMock.ResponseBuilders;
using WireMock.Server;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;

namespace EntraMcpProxy.IntegrationTests.Fixtures;

public sealed class FakeEntra : IAsyncDisposable
{
    private readonly WireMockServer _server;
    public string Url => _server.Url!;
    public string TenantId { get; }
    public RsaSecurityKey SigningKey { get; }

    public FakeEntra(string tenantId)
    {
        TenantId = tenantId;
        var rsa = RSA.Create(2048);
        SigningKey = new RsaSecurityKey(rsa) { KeyId = "test-key-1" };
        _server = WireMockServer.Start();
        SetupOpenIdConfiguration();
        SetupJwks();
        SetupTokenEndpoint();
    }

    private void SetupOpenIdConfiguration()
    {
        var cfg = new {
            issuer = $"{Url}/{TenantId}/v2.0",
            jwks_uri = $"{Url}/{TenantId}/discovery/v2.0/keys",
            authorization_endpoint = $"{Url}/{TenantId}/oauth2/v2.0/authorize",
            token_endpoint = $"{Url}/{TenantId}/oauth2/v2.0/token",
            id_token_signing_alg_values_supported = new[] { "RS256" },
            response_types_supported = new[] { "code" },
        };
        _server.Given(Request.Create().WithPath($"/{TenantId}/v2.0/.well-known/openid-configuration").UsingGet())
               .RespondWith(Response.Create().WithBodyAsJson(cfg));
    }

    private void SetupJwks() { /* RSA params → JWKS keys array; abbreviated — full impl in helper file */ }

    private void SetupTokenEndpoint()
    {
        _server.Given(Request.Create().WithPath($"/{TenantId}/oauth2/v2.0/token").UsingPost())
               .RespondWith(Response.Create().WithStatusCode(200).WithBodyAsJson(new {
                   access_token = "stub-downstream-token",
                   expires_in = 3600,
                   token_type = "Bearer"
               }));
    }

    public string IssueUserToken(string oid, string scope = "user_impersonation")
    {
        var claims = new[] {
            new Claim("oid", oid),
            new Claim("tid", TenantId),
            new Claim("scp", scope),
            new Claim("aud", "api://test-client-id"),
            new Claim("iss", $"{Url}/{TenantId}/v2.0"),
        };
        var token = new JwtSecurityToken(
            issuer: $"{Url}/{TenantId}/v2.0",
            audience: "api://test-client-id",
            claims: claims,
            notBefore: DateTime.UtcNow.AddMinutes(-1),
            expires: DateTime.UtcNow.AddMinutes(30),
            signingCredentials: new SigningCredentials(SigningKey, SecurityAlgorithms.RsaSha256));
        return new JwtSecurityTokenHandler().WriteToken(token);
    }

    public ValueTask DisposeAsync() { _server.Dispose(); return ValueTask.CompletedTask; }
}
```

- [ ] **Step 2: Adapter test**

```csharp
[Fact]
public async Task FakeEntra_serves_openid_configuration()
{
    await using var entra = new FakeEntra(Guid.NewGuid().ToString());
    using var http = new HttpClient();
    var resp = await http.GetAsync($"{entra.Url}/{entra.TenantId}/v2.0/.well-known/openid-configuration");
    resp.StatusCode.Should().Be(HttpStatusCode.OK);
}
```

Run + commit: `test: add WireMock fake Entra fixture`

### Task 1.4: WireMock helper for fake downstream MCP

**Files:** Create `EntraMcpProxy.IntegrationTests/Fixtures/FakeDownstreamMcp.cs`

- [ ] Implement minimal MCP-over-HTTP stub responding to `initialize`, `tools/list`, `tools/call`. Record each request (including received `Authorization` header) into an in-memory `ConcurrentBag<RecordedCall>` for test assertions. Smoke test asserts a call against it is recorded with the bearer it received. Commit: `test: add WireMock fake downstream MCP`

### Task 1.5: E2E test project

**Files:** Create `EntraMcpProxy.E2ETests/EntraMcpProxy.E2ETests.csproj`, `EntraMcpProxy.E2ETests/Fixtures/ProxyContainerFixture.cs`

- [ ] **Step 1: csproj** mirrors 1.2 + adds `Testcontainers`.

- [ ] **Step 2: Container fixture** that:
  - builds the proxy image (`Dockerfile`)
  - starts a WireMock container as Entra, a WireMock container as downstream MCP
  - starts the proxy container with environment variables pointed at those mocks
  - exposes the proxy's public URL to tests via `HttpClient`

- [ ] **Step 3: Smoke test**

```csharp
[Fact]
public async Task Healthz_via_container_returns_200()
{
    await using var fx = await ProxyContainerFixture.StartAsync();
    var resp = await fx.Http.GetAsync("/api/healthz");
    resp.StatusCode.Should().Be(HttpStatusCode.OK);
}
```

Run + commit: `test: add E2E test project with Testcontainers`

---

# Phase 2 — SDK Transport Semantics Probe

**Goal:** Empirically determine whether `ModelContextProtocol 0.7.0-preview.1` reissues the `Authorization` header per HTTP request or pins it at session establishment. This decision shapes Phase 8. **Refs: C2 (decision input).**

### Task 2.1: Probe test

**Files:** Create `EntraMcpProxy.IntegrationTests/SdkTransportProbeTests.cs`

- [ ] **Step 1: Test**

```csharp
[Fact]
public async Task McpClient_reauthorizes_per_tool_call()
{
    await using var downstream = new FakeDownstreamMcp();
    // Build a real McpClient against the fake downstream with a DelegatingHandler that
    // attaches a header reading from AsyncLocal<string>. Issue two CallToolAsync from
    // two different AsyncLocal values. Assert downstream received two different headers.
    var asyncToken = new AsyncLocal<string>();
    var handler = new HeaderInjector(() => asyncToken.Value ?? "MISSING");
    using var http = new HttpClient(handler) { /* ... */ };
    var client = await McpClient.CreateAsync(/* transport over http to downstream.Url */);

    asyncToken.Value = "userA-token";
    await client.CallToolAsync(new() { Name = "ping" });
    asyncToken.Value = "userB-token";
    await client.CallToolAsync(new() { Name = "ping" });

    downstream.RecordedCalls.Select(c => c.Authorization).Should().BeEquivalentTo(
        new[] { "Bearer userA-token", "Bearer userB-token" });
}
```

- [ ] **Step 2: Run + capture result**

Two outcomes drive Phase 8:
- **PASS:** SDK re-attaches per request → Phase 8 keeps singleton `McpClient` per downstream, removes SP fallback, ensures `IHttpContextAccessor` flows correctly.
- **FAIL:** SDK pins at session → Phase 8 rewrites `DownstreamClientManager` to per-user clients with idle eviction.

Record the outcome in a comment at the top of `Services/DownstreamClientManager.cs` and in this plan as a checkbox below.

- [ ] **Step 3: Result captured**

- [ ] Per-request semantics confirmed
- [ ] Per-session semantics confirmed (per-user client lifecycle required)

Commit: `test: SDK transport semantics probe (Refs: C2 decision input)`

---

# Phase 3 — Strong-Typed Options + Startup Validation

**Goal:** Configuration model is strongly typed, validated at startup, and fails fast on misconfiguration. **Refs: M11, N1, N18, L18.**

### Task 3.1: `EntraIdOptions`

**Files:** Create `Configuration/EntraIdOptions.cs`, `EntraMcpProxy.Tests/Configuration/EntraIdOptionsTests.cs`

- [ ] **Step 1: Failing test**

```csharp
[Fact]
public void Validator_rejects_missing_tenantId()
{
    var opts = new EntraIdOptions { Authority = "https://login.microsoftonline.com/abc/v2.0", ClientId = "id" };
    var result = new EntraIdOptionsValidator().Validate(null, opts);
    result.Failed.Should().BeTrue();
    result.FailureMessage.Should().Contain("TenantId");
}
```

- [ ] **Step 2: Run red.** Expected: type not defined.

- [ ] **Step 3: Implement**

```csharp
public sealed class EntraIdOptions
{
    public string Authority { get; init; } = "";
    public string TenantId { get; init; } = "";
    public string ClientId { get; init; } = "";
    public bool RequireHttpsMetadata { get; init; } = true;
}

public sealed class EntraIdOptionsValidator : IValidateOptions<EntraIdOptions>
{
    public ValidateOptionsResult Validate(string? name, EntraIdOptions o)
    {
        var errs = new List<string>();
        if (!Uri.TryCreate(o.Authority, UriKind.Absolute, out _)) errs.Add("Authority must be an absolute URL.");
        if (!Guid.TryParse(o.TenantId, out _)) errs.Add("TenantId must be a GUID.");
        if (!Guid.TryParse(o.ClientId, out _)) errs.Add("ClientId must be a GUID.");
        return errs.Count == 0 ? ValidateOptionsResult.Success : ValidateOptionsResult.Fail(string.Join("; ", errs));
    }
}
```

- [ ] **Step 4:** Green + commit.

### Task 3.2: `ProxyOptions`

**Files:** Create `Configuration/ProxyOptions.cs`, tests

- [ ] **Tests cover:**
  - `PublicBaseUrl` is required, must be `https://...`
  - `AllowedRedirectUris` non-empty
  - `EgressAllowlist` non-empty for prod env
  - `RefreshIntervalMinutes` in `[1, 60]`
  - `RateLimit.RequestsPerMinute` in `[1, 10_000]`

- [ ] **Implement** with `IValidateOptions<ProxyOptions>`.

- [ ] Commit.

### Task 3.3: `DownstreamServerOptions` replaces `DownstreamServerConfig`

**Files:** Create `Configuration/DownstreamServerOptions.cs`, delete `Configuration/DownstreamServerConfig.cs`

- [ ] Tests:
  - `OBO.ClientSecret` required when `AuthType = "OBOToken"`
  - `Prefix` required, lowercase, no `__`, no whitespace
  - `BaseUrl` host must appear in `Proxy:EgressAllowlist`
  - `TargetScope` matches `{guid}/{name}` shape

- [ ] Implement + wire into `IValidateOptions`. Note: cross-options validation (BaseUrl against EgressAllowlist) requires `IPostConfigure<List<DownstreamServerOptions>>` or composite validator with `IOptions<ProxyOptions>`.

- [ ] Commit.

### Task 3.4: Refuse to start with dev config in prod

**Files:** Modify `Program.cs`

- [ ] **Test (integration):**

```csharp
[Fact]
public async Task App_refuses_to_start_when_dev_env_with_RequireHttpsMetadata_false_in_prod()
{
    var factory = new ProxyAppFactory { /* env=Production, RequireHttpsMetadata=false */ };
    var act = async () => await factory.CreateClient().GetAsync("/api/healthz");
    await act.Should().ThrowAsync<InvalidOperationException>();
}
```

- [ ] **Implement guard** in Program bootstrap: if `env.IsProduction() && options.RequireHttpsMetadata == false` → throw at startup.

- [ ] Commit `Refs: N18`.

### Task 3.5: `appsettings.json` references env vars only (no inline secrets)

**Files:** Modify `appsettings.json`

- [ ] Remove `OBO.ClientSecret` placeholder entirely. Update README in Phase 16 to show env-var binding.

- [ ] Commit `Refs: N1`.

---

# Phase 4 — PublicBaseUrl & ForwardedHeaders Lockdown

**Goal:** Discovery / metadata / `WWW-Authenticate` URLs derive from a configured `PublicBaseUrl` — never from `Host` or `X-Forwarded-Host`. **Refs: H5, L20.**

### Task 4.1: `PublicBaseUrlAccessor`

**Files:** Create `Infrastructure/PublicBaseUrlAccessor.cs`, tests

- [ ] **Test**

```csharp
[Fact]
public void Returns_configured_value_ignoring_request()
{
    var opts = Options.Create(new ProxyOptions { PublicBaseUrl = "https://canon.example.com" });
    var sut = new PublicBaseUrlAccessor(opts);
    sut.Get().Should().Be("https://canon.example.com");
}
```

- [ ] **Implement**

```csharp
public interface IPublicBaseUrlAccessor { string Get(); }
public sealed class PublicBaseUrlAccessor(IOptions<ProxyOptions> opts) : IPublicBaseUrlAccessor
{
    public string Get() => opts.Value.PublicBaseUrl.TrimEnd('/');
}
```

- [ ] Commit.

### Task 4.2: Discovery / metadata / WWW-Authenticate use accessor

**Files:** Modify `Program.cs`

- [ ] Replace every `$"{scheme}://{host}"` with `accessor.Get()` in:
  - `/.well-known/openid-configuration`
  - `/.well-known/oauth-protected-resource`
  - `WWW-Authenticate` middleware

- [ ] **Integration test for spoof attack**

```csharp
[Fact]
public async Task Discovery_endpoint_ignores_XForwardedHost()
{
    await using var fx = await TestEnv.StartAsync();
    fx.Http.DefaultRequestHeaders.Add("X-Forwarded-Host", "evil.example.com");
    var resp = await fx.Http.GetAsync("/.well-known/openid-configuration");
    var json = await resp.Content.ReadFromJsonAsync<JsonElement>();
    json.GetProperty("issuer").GetString().Should().Be("https://proxy.test");
    json.GetProperty("issuer").GetString().Should().NotContain("evil");
}
```

- [ ] Commit `Refs: H5`.

### Task 4.3: Remove unsafe `UseForwardedHeaders` defaults

**Files:** Modify `Program.cs`

- [ ] **Either**: remove `UseForwardedHeaders` call entirely (preferred — accessor handles base URL), **or** restrict `KnownNetworks` to the ingress pod CIDR via `ProxyOptions.TrustedProxyNetworks`. Default to "removed".

- [ ] Add test asserting `Request.Scheme` is whatever Kestrel saw (not influenced by `X-Forwarded-Proto`).

- [ ] Commit `Refs: H5`.

---

# Phase 5 — OAuth Facade Hardening

**Goal:** `/authorize` and `/token` defend in depth and stop being open relays. **Refs: H3, H4, M8, M9, M10, M12, M13.**

### Task 5.1: `RedirectUriValidator`

**Files:** Create `Auth/RedirectUriValidator.cs`, tests

- [ ] Test rejects: unlisted URIs, `javascript:` schemes, path traversal, hosts with trailing whitespace, suffix-match attacks (`https://claude.ai.evil.com/...`).
- [ ] Implement using exact-string comparison against `ProxyOptions.AllowedRedirectUris`.
- [ ] Commit `Refs: H3`.

### Task 5.2: Enforce allowlist in `/authorize`

**Files:** Modify `Program.cs`

- [ ] Integration test: request to `/authorize?redirect_uri=https://evil.com/cb` returns `400`.
- [ ] Wire validator before redirect construction; return `Results.BadRequest("redirect_uri not allowed")`.
- [ ] Commit `Refs: H3`.

### Task 5.3: `PkceValidator`

**Files:** Create `Auth/PkceValidator.cs`, tests

- [ ] Test: missing `code_challenge` → fail; method != `S256` → fail; valid pair → pass; verifier length validation per RFC 7636.
- [ ] Implement.
- [ ] Commit `Refs: H4`.

### Task 5.4: Enforce PKCE in `/authorize`

- [ ] Integration test: request without `code_challenge` returns `400`.
- [ ] Wire validator.
- [ ] Commit `Refs: H4`.

### Task 5.5: Restrict CORS

**Files:** Modify `Program.cs`

- [ ] Replace `AllowAnyOrigin()` with explicit policy bound to `ProxyOptions.AllowedCorsOrigins` (default: `[]` → CORS effectively disabled).
- [ ] Test: cross-origin preflight from `https://evil.com` returns 0 `Access-Control-Allow-Origin`.
- [ ] Commit `Refs: M8`.

### Task 5.6: `/token` uses `IHttpClientFactory`

**Files:** Modify `Program.cs`

- [ ] Register `services.AddHttpClient("entra-token-relay", c => c.BaseAddress = new Uri(authority));`
- [ ] `/token` handler resolves `IHttpClientFactory` and creates client via factory.
- [ ] Test: 100 sequential POSTs to `/token` do not exhaust sockets (assert via Process.GetCurrentProcess() open handles — best-effort heuristic).
- [ ] Commit `Refs: M9`.

### Task 5.7: Rate limiting

**Files:** Modify `Program.cs`

- [ ] Add `services.AddRateLimiter(...)` with fixed-window: `/authorize` and `/token` capped at 30 req/min per IP (configurable).
- [ ] Test: 31st request within 60s returns `429`.
- [ ] Commit `Refs: M10`.

### Task 5.8: Body size limit on `/token`

- [ ] Test: POST 2MB body to `/token` → `413`.
- [ ] Implement with `[RequestSizeLimit(8 * 1024)]` or middleware on the endpoint.
- [ ] Commit `Refs: M13`.

### Task 5.9: Document `client_secret` trust assumption (deferred to docs phase, but link from threat-model.md stub here)

- [ ] Add `docs/threat-model.md` with placeholder "client_secret held by Anthropic — see Phase 16 docs phase".
- [ ] Commit `Refs: M12`.

---

# Phase 6 — JWT Validation Explicit

**Goal:** Token validation is explicit and any future maintainer breaking it triggers a test failure. **Refs: N13, N14, L17.**

> **Prerequisite (raised during Task 1.3 review)**: The current `Program.cs` does not set `MapInboundClaims = false`. The default `JwtSecurityTokenHandler` rewrites `oid` → `http://schemas.microsoft.com/identity/claims/objectidentifier` and `tid` → `http://schemas.microsoft.com/identity/claims/tenantid`. Phase 7's OBO cache key derives from `oid` and `tid` by short name and will silently read `null` if this is not corrected here. **Task 6.1 must explicitly set `MapInboundClaims = false` on the JWT bearer options** (or migrate to `JsonWebTokenHandler` which doesn't map claims by default) before any later phase reads claims by short name.

### Task 6.1: Explicit validation parameters

**Files:** Modify `Program.cs`

- [ ] Set all of: `ValidateIssuer = true`, `ValidateLifetime = true`, `ValidateIssuerSigningKey = true`, `ValidateAudience = true`, `SaveSigninToken = false`, `ClockSkew = TimeSpan.FromMinutes(2)`.
- [ ] Test (integration): JWT with `exp` 3 min in the past returns `401`. JWT with `iss=https://attacker.com` returns `401`. Unsigned JWT returns `401`.
- [ ] Commit `Refs: N13`.

### Task 6.2: Confirm `MapMcp()` routes are protected

**Files:** Modify `Program.cs`

- [ ] Add `app.MapMcp().RequireAuthorization();`
- [ ] **Integration test:**

```csharp
[Fact]
public async Task MCP_routes_return_401_without_bearer()
{
    await using var fx = await TestEnv.StartAsync();
    var resp = await fx.Http.PostAsync("/mcp", new StringContent("{}", Encoding.UTF8, "application/json"));
    resp.StatusCode.Should().Be(HttpStatusCode.Unauthorized);
    resp.Headers.WwwAuthenticate.ToString().Should().Contain("Bearer");
}
```

- [ ] Commit `Refs: N14`.

---

# Phase 7 — OBO Cache Rewrite

**Goal:** Cache keys are derived from validated claims, never from raw-token hashes. Eviction enforced. Cross-user leakage impossible. **Refs: C1, M14, N2.**

### Task 7.1: `OboCacheKey`

**Files:** Create `Auth/OboCacheKey.cs`, tests

- [ ] **Failing test**

```csharp
[Fact]
public void Two_users_produce_different_keys_for_same_scope()
{
    var k1 = OboCacheKey.From(oid: "alice", tid: "T", aud: "A", scope: "S");
    var k2 = OboCacheKey.From(oid: "bob",   tid: "T", aud: "A", scope: "S");
    k1.Should().NotBe(k2);
}

[Fact]
public void Same_user_same_scope_produces_same_key()
{
    OboCacheKey.From("alice", "T", "A", "S").Should().Be(OboCacheKey.From("alice", "T", "A", "S"));
}
```

- [ ] **Implement** as a `readonly record struct` with deterministic string composition + `IEquatable<>`.

- [ ] Commit.

### Task 7.2: `EntraIdOBOHandler` keys cache on `OboCacheKey`

**Files:** Modify `Auth/EntraIdOBOHandler.cs`

- [ ] **Critical test (collision PoC):**

```csharp
[Fact]
public async Task Two_different_tokens_with_same_GetHashCode_do_NOT_share_cache_entry()
{
    // Find or construct two strings with same GetHashCode in this process;
    // verify the new handler returns *different* OBO tokens for them.
    // If we cannot construct a collision in reasonable time, fall back to a
    // deterministic NSubstitute-based test asserting that cache lookups use
    // OboCacheKey, not GetHashCode (i.e., a refactor test).
}
```

- [ ] **Implement**: extract `oid`/`tid`/`aud` from the validated `ClaimsPrincipal` (use `IHttpContextAccessor.HttpContext?.User`). For background flows, claims absent → bypass cache + use Phase 8 SP path. Cache value: `OboCacheKey → (token, exp)`.

- [ ] Commit `Refs: C1`.

### Task 7.3: Cache eviction sweeper

**Files:** Modify `Auth/EntraIdOBOHandler.cs`

- [ ] Add `PeriodicTimer`-based background sweeper that removes entries past `exp`. Wire as `IHostedService`.
- [ ] Test (unit): adding 100 expired entries then triggering sweep removes all.
- [ ] Commit `Refs: M14`.

### Task 7.4: TTL reduction toward revocation propagation

- [ ] Cache TTL capped at `min(expires_in, 10 min)`.
- [ ] Test: an issued token with `expires_in=3600` is cached for at most 600s.
- [ ] Commit `Refs: N2`.

### Task 7.5: Sanitize Entra error before throwing

**Files:** Modify `Auth/EntraIdOBOHandler.cs`

- [ ] Replace `throw new InvalidOperationException($"... {body}")` with `throw new OboExchangeException("OBO exchange failed.", innerBody: body)`. New exception type carries the raw body in a non-`Message` property used only by logging.
- [ ] Test: catching the exception, `ex.Message` does not contain Entra body.
- [ ] Commit `Refs: H7 (partial)`.

---

# Phase 8 — Downstream Client + SP Fallback

**Goal:** Per-user identity flows correctly to every downstream MCP call. Silent SP fallback eliminated. **Refs: C2, H6, N3.** Shape depends on Phase 2 outcome.

### Task 8.1: Remove silent SP fallback path

**Files:** Modify `Auth/EntraIdOBOHandler.cs`

- [ ] Test (unit): `SendAsync` with no `HttpContext` AND no opt-in `IsDiscoveryContext` flag throws `InvalidOperationException("No user context and discovery flag not set")`.
- [ ] Implement: introduce `IDiscoveryContext` ambient marker (AsyncLocal scope set only by `ToolAggregatorService`). Only when set do we use `GetSpTokenAsync`.
- [ ] Commit `Refs: H6, N3`.

### Task 8.2: SP discovery token uses explicit scope (not `.default`)

**Files:** Modify `Auth/EntraIdOBOHandler.cs`, `Configuration/DownstreamServerOptions.cs`

- [ ] Add `OBO.DiscoveryScope` config. If absent, discovery is *disabled* — tools/list runs lazily on first user request.
- [ ] Test: SP request body posts the configured discovery scope, never `.default`.
- [ ] Commit `Refs: N3`.

### Task 8.3 (a) — IF Phase 2 = per-request: singleton client + audited flow

**Files:** Modify `Services/DownstreamClientManager.cs`

- [ ] Keep one `McpClient` per prefix.
- [ ] **Two-user concurrency test** (integration):

```csharp
[Fact(Timeout=30_000)]
public async Task Two_concurrent_users_get_their_own_OBO_tokens()
{
    await using var entra = new FakeEntra(TenantId);
    await using var dn    = new FakeDownstreamMcp();
    await using var fx    = await TestEnv.StartAsync(entra, dn);

    var alice = entra.IssueUserToken(oid: "alice");
    var bob   = entra.IssueUserToken(oid: "bob");

    var aliceCalls = Enumerable.Range(0, 50).Select(_ => fx.CallToolAs(alice, "azdevops__ping"));
    var bobCalls   = Enumerable.Range(0, 50).Select(_ => fx.CallToolAs(bob,   "azdevops__ping"));
    await Task.WhenAll(aliceCalls.Concat(bobCalls));

    dn.RecordedCalls.Should().HaveCount(100);
    dn.RecordedCalls
      .GroupBy(c => c.OboExchangedFromOid)
      .Select(g => g.Key)
      .Should().BeEquivalentTo(new[] { "alice", "bob" });
    dn.RecordedCalls.Should().OnlyContain(c =>
        (c.OboExchangedFromOid == "alice") == c.OriginalAuth.Contains("oid:alice")
     || (c.OboExchangedFromOid == "bob")   == c.OriginalAuth.Contains("oid:bob"));
}
```

The `FakeDownstreamMcp` and `FakeEntra` correlate the OBO exchange (`assertion` parameter) with the originating user JWT so the test can prove no cross-user leakage.

- [ ] Commit `Refs: C2`.

### Task 8.3 (b) — IF Phase 2 = per-session: per-user client lifecycle

**Files:** Rewrite `Services/DownstreamClientManager.cs`

- [ ] Cache key changes from `prefix` to `(prefix, oid)`.
- [ ] Idle eviction sweeper disposes `McpClient` instances unused for >10 min.
- [ ] Tool discovery moves to discovery-only path with explicit `IDiscoveryContext`.
- [ ] Concurrency test (same as 8.3a) plus:

```csharp
[Fact]
public async Task Idle_McpClient_for_user_is_disposed_after_TTL()
{
    // exercise as user A, wait > eviction TTL, assert McpClient disposed
}
```

- [ ] Commit `Refs: C2`.

### Task 8.4: Verify `IHttpContextAccessor` flows under load

- [ ] Stress test using `NBomber` or simple `Parallel.ForEachAsync`, 50 concurrent users, 10s.
- [ ] Assertion: zero downstream calls carry the wrong user's OID.
- [ ] Commit `Refs: C2 (verification)`.

---

# Phase 9 — Tool Poisoning Defense

**Goal:** Adversarial tool metadata from a downstream cannot reach the model unfiltered. Tool-set changes are diffed and audited. **Refs: N5, N6, N7, M15.**

### Task 9.1: Tool name allowlist per downstream

**Files:** Modify `Configuration/DownstreamServerOptions.cs`, `Services/ToolAggregatorService.cs`, tests

- [ ] Add `AllowedTools: List<string>` on the downstream config. If `null/empty`, behavior depends on `AllowUnknownTools` flag (default `false`).
- [ ] Test: `RegisterTools` filters out tools not in the allowlist; an unknown tool is recorded in pending list, not registered.
- [ ] Commit `Refs: N5`.

### Task 9.2: Tool description sanitizer + provenance wrapping

**Files:** Create `Services/ToolPolicyService.cs`, tests

- [ ] Sanitizer:
  - strips imperative second-person directives (configurable regex set)
  - prepends `[Source: downstream={prefix} tool={original}]\n` provenance marker
  - rejects descriptions > N chars
- [ ] `InputSchema` validator: rejects schemas containing `$ref` to external URIs, `allOf` cycles, vendor extensions (`x-*`).
- [ ] Tests: malicious description gets sanitized; provenance marker present; reject on external `$ref`.
- [ ] Wire into `ToolRegistry.RegisterTools`.
- [ ] Commit `Refs: N5`.

### Task 9.3: Tool-set diff + audit on refresh

**Files:** Modify `Services/ToolAggregatorService.cs`

- [ ] Compute SHA-256 over normalized tool-set per downstream.
- [ ] On hash change: log structured `tool_set_changed` audit event with `{added, removed, description_changed}` lists.
- [ ] Test: when stub downstream changes a tool description between two refreshes, audit event emitted.
- [ ] Commit `Refs: N6`.

### Task 9.4: Fix `RegisterTools` substring prefix bug

**Files:** Modify `Services/ToolRegistry.cs`

- [ ] Change `StartsWith($"{prefix}__")` removal to exact-prefix match using a `(prefix, originalName) → entry` dictionary indexed on the tuple, not a flat string key.
- [ ] Add config validation: `prefix` must match `^[a-z][a-z0-9_]{1,30}$` and must not contain `__`.
- [ ] Test: two prefixes `ado` and `ado2` do not interfere on registration.
- [ ] Commit `Refs: N7, M15`.

---

# Phase 10 — Tool Result Poisoning Defense

**Goal:** Tool call results carry provenance markers and are size-bounded before reaching the model. **Refs: N11, N12.**

### Task 10.1: Provenance wrapping of `CallToolResult`

**Files:** Modify `Services/ProxyToolHandler.cs`, tests

- [ ] On every tool call result, wrap each `TextContent` block with a clearly-delimited block:
  ```
  <<<DOWNSTREAM_CONTENT source="{prefix}" tool="{original}" user_oid="{oid}" call_id="{guid}">>>
  {original content}
  <<<END_DOWNSTREAM_CONTENT>>>
  ```
- [ ] Non-text content (images, embedded resources) passes through unchanged (no model-instruction surface there).
- [ ] Test: a downstream returning text content `"IGNORE PRIOR INSTRUCTIONS"` arrives at the MCP server wrapped in markers.
- [ ] Commit `Refs: N11`.

### Task 10.2: Response size budget

**Files:** Modify `Services/ProxyToolHandler.cs`

- [ ] `ProxyOptions.ToolResult.MaxBytes` (default 256 KB) — content beyond budget is truncated with `[truncated: original=NNN bytes]`.
- [ ] Test: 1 MB downstream response is truncated and marker is present.
- [ ] Commit `Refs: N12`.

---

# Phase 11 — Per-Tool Authorization

**Goal:** Authenticated users only see and invoke tools they are authorized for. **Refs: N4, N21.**

### Task 11.1: `AuthorizationPolicyOptions`

**Files:** Create `Configuration/AuthorizationPolicyOptions.cs`, tests

- [ ] Schema:
  ```json
  {
    "TenantId": "{tid}",
    "DefaultGroups": ["{group-oid}"],
    "Tools": {
      "azdevops__create_work_item": { "AllowedGroups": ["devops-write"] },
      "azdevops__*": { "AllowedGroups": ["devops-users"] }
    }
  }
  ```
- [ ] Validator: tool keys must contain `__`; group values must be GUIDs.
- [ ] Commit.

### Task 11.2: `DownstreamAuthorizationFilter`

**Files:** Create `Auth/DownstreamAuthorizationFilter.cs`, tests

- [ ] `bool IsAllowed(ClaimsPrincipal user, string prefixedName)` — wildcard matching with most-specific rule wins.
- [ ] Tests: allow/deny matrix from spec table; user with no relevant claim denied; admin override via config.
- [ ] Commit `Refs: N4`.

### Task 11.3: Apply in `HandleListToolsAsync` and `HandleCallToolAsync`

**Files:** Modify `Services/ProxyToolHandler.cs`

- [ ] `ListTools` returns only authorized tools per user.
- [ ] `CallTool` on unauthorized tool returns MCP error `not_authorized` (and audit-logs the attempt).
- [ ] Tests:
  - User in `devops-users` sees `azdevops__list_projects` but not `azdevops__create_work_item`.
  - Unauthorized call returns error + audit event emitted.
- [ ] Commit `Refs: N4, N21`.

---

# Phase 12 — Audit & Telemetry

**Goal:** Every security-relevant event leaves a structured audit record with stable schema. **Refs: N16, N17.**

### Task 12.1: `AuditLog` emitter

**Files:** Create `Infrastructure/AuditLog.cs`, tests

- [ ] Single facade emitting JSON via dedicated `ILogger` category `EntraMcpProxy.Audit`.
- [ ] Events: `tool_invocation`, `tool_set_changed`, `authz_denied`, `obo_exchange_failed`, `pkce_missing`, `redirect_uri_rejected`, `forwarded_host_ignored`, `cache_eviction`.
- [ ] Schema:
  ```json
  { "ts":"...","event":"tool_invocation","user_oid":"...","tid":"...",
    "tool":"azdevops__list_projects","args_sha256":"...","downstream_status":"success",
    "latency_ms":123,"call_id":"..." }
  ```
- [ ] Args are SHA-256-hashed only, never logged in plaintext.
- [ ] Tests: each emitter shape verified against a captured `LogRecord`.
- [ ] Commit `Refs: N16`.

### Task 12.2: Wire `AuditLog` into all event sites

**Files:** Modify `Services/ProxyToolHandler.cs`, `Services/ToolAggregatorService.cs`, `Auth/*`, `Program.cs`

- [ ] One call per event site.
- [ ] Test: integration test asserts each user action produces exactly one audit row.
- [ ] Commit `Refs: N16`.

### Task 12.3: Strip downstream content from operational logs

**Files:** Modify `Services/ProxyToolHandler.cs`

- [ ] Replace the `result.Content.ToString()` warning log with a status-only log (`isError=true count=N`).
- [ ] Test: simulate isError downstream response; assert no PII content in captured logs.
- [ ] Commit `Refs: N17`.

---

# Phase 13 — Egress Allowlist

**Goal:** The proxy can only call downstream hosts explicitly permitted in `ProxyOptions.EgressAllowlist`. **Refs: N19, N20.**

### Task 13.1: `EgressAllowlist` validator

**Files:** Create `Infrastructure/EgressAllowlist.cs`, tests

- [ ] `bool IsAllowed(Uri)` — host-suffix match; explicit denial logs at audit level.
- [ ] Validate at startup: every `DownstreamServerOptions.BaseUrl.Host` is in the allowlist.
- [ ] Commit `Refs: N19`.

### Task 13.2: Per-request egress enforcement

**Files:** Modify `Auth/EntraIdOBOHandler.cs` (or a wrapping `DelegatingHandler`)

- [ ] Reject outbound request whose host is not in the allowlist (defense in depth against runtime config drift).
- [ ] Test: setting `BaseUrl` to a non-allowlisted host post-startup rejects the request at send time.
- [ ] Commit `Refs: N19`.

---

# Phase 14 — GlobalExceptionHandler Hardening

**Goal:** No path returns Entra internal details or auth-related exception messages to the client. **Refs: H7.**

### Task 14.1: Rewrite mapping

**Files:** Modify `Infrastructure/GlobalExceptionHandler.cs`, tests

- [ ] Treat `OboExchangeException` and `InvalidOperationException` from auth namespace as 500-class for purposes of the detail policy: return generic message in production; full detail only in `IsDevelopment()`.
- [ ] Tests:
  - Throwing `OboExchangeException` from a controller in `Production` returns body whose `detail` does not contain the inner Entra body.
  - Same in `Development` does contain it (developer ergonomics).
- [ ] Commit `Refs: H7`.

---

# Phase 15 — Docker-Based End-to-End Test Suite

**Goal:** Real container running real proxy code, behind WireMock-backed fake Entra and WireMock-backed fake downstream MCP, exercises every critical path end to end. **Refs: full coverage gate.**

### Task 15.1: `docker-compose.e2e.yml`

**Files:** Create `docker-compose.e2e.yml`, `e2e/wiremock-entra/`, `e2e/wiremock-downstream/`

- [ ] Three services: `proxy` (built from `Dockerfile`), `entra` (WireMock with mounted mappings), `downstream` (WireMock with mounted mappings).
- [ ] Proxy env vars point at the WireMock URLs.
- [ ] Health-check service waits for `/api/healthz`.

### Task 15.2: E2E test for full happy-path identity flow

**Files:** Create `EntraMcpProxy.E2ETests/HappyPathTests.cs`

- [ ] Steps:
  1. Start compose
  2. `GET /authorize?...&code_challenge=...` → expect 302 to Entra mock
  3. Mock Entra exchange returns code → POST `/token` with code+verifier → expect 200 with id_token
  4. POST `/mcp` `tools/list` with bearer → expect tools list filtered/wrapped per Phase 9
  5. POST `/mcp` `tools/call` → expect downstream call with correct OBO token (verified via WireMock-downstream recorded calls)
- [ ] Asserts: every audit event emitted; no log leak; no Entra body in any 4xx response.
- [ ] Commit.

### Task 15.3: E2E security tests

Each as a separate test file under `EntraMcpProxy.E2ETests/Security/`:

- [ ] `RedirectUriRejection_Tests.cs` — `/authorize` with foreign `redirect_uri` returns 400.
- [ ] `PkceMissing_Tests.cs` — `/authorize` without `code_challenge` returns 400.
- [ ] `ForwardedHostSpoof_Tests.cs` — discovery doc returns configured URL regardless of `X-Forwarded-Host`.
- [ ] `TwoUserConcurrency_Tests.cs` — N parallel users; downstream recorded calls show 1:1 oid mapping (the C2 verification, end to end in container).
- [ ] `RateLimit_Tests.cs` — 31st request to `/token` in a minute returns 429.
- [ ] `ToolPoisoning_Tests.cs` — downstream serves a poisoned tool description; proxy registration filters or wraps it.
- [ ] `EgressAllowlist_Tests.cs` — adding a host outside allowlist fails startup validation.
- [ ] `JwtRejections_Tests.cs` — bad signature, expired, wrong issuer, wrong audience each return 401.
- [ ] `AuditTrail_Tests.cs` — full user journey produces exactly the expected sequence of audit events.

Commit per file.

### Task 15.4: Hook E2E into CI

- [ ] Add `e2e` job to `.github/workflows/ci.yml` (already added in Task 0.3 — verify and adjust).
- [ ] Commit.

---

# Phase 16 — Documentation

**Goal:** README, threat model, and operations docs reflect the *fixed* design — and explain what's still residually risky. **Refs: N1, L20, M12, N20.**

### Task 16.1: README rewrite

**Files:** Modify `README.md`

- [ ] Sections to update:
  - Configuration: env-var binding examples (no inline JSON secrets). Reference Azure Key Vault provider.
  - Deployment: pinned image digests; CI requirements; environment-prod gating.
  - Architecture: remove the misleading "every downstream call uses the user's identity" claim until the Phase 2 outcome is documented. Replace with the actual flow (per-request OR per-user-client based on probe result).
  - Operations: link to `docs/operations.md`.
  - Security: link to `docs/threat-model.md`.
- [ ] Commit `Refs: N1, L20`.

### Task 16.2: `docs/threat-model.md`

- [ ] Content:
  - Trust assumptions (notably: Claude Web holds the Entra `client_secret`)
  - Residual risks (e.g., per-user authorization at the proxy is opt-in; downstream MCPs that pre-date Phase 9 may bypass description sanitizing if not configured)
  - Defense-in-depth layers and what each defends against
- [ ] Commit `Refs: M12`.

### Task 16.3: `docs/operations.md`

- [ ] Deployment governance checklist:
  - Pre-deployment: CI green, vulnerability scan clean, SBOM published
  - Change control for new `DownstreamServers` entries
  - Secret rotation procedure (Entra client_secret)
  - Log retention and audit-trail destination
  - Incident response runbook (revoke client_secret, roll deployment, query audit log)
- [ ] Commit `Refs: N20`.

---

# Phase 17 — Final Verification

**Goal:** All findings closed, all tests green, no known regressions. **Refs: full audit closure.**

### Task 17.1: Coverage check

- [ ] Run `dotnet test --collect:"XPlat Code Coverage"` — assert >85% line coverage on `Auth/`, `Services/`, `Infrastructure/`.
- [ ] If gaps: add tests until threshold met or document why (e.g., `Program.cs` bootstrap is exercised by integration tests instead).

### Task 17.2: Vulnerability scan

- [ ] Run `dotnet list package --vulnerable --include-transitive` — expect zero Critical / High.

### Task 17.3: Audit closure log

- [ ] Append to `audit/2026-05-21-security-review.md` a closing section with each finding ID and the commit SHA(s) that closed it.

### Task 17.4: Tag pre-deployment candidate

- [ ] `git tag v0.1.0-prerelease`.
- [ ] Build container image with the tagged SHA; smoke-test deploy in a sandbox cluster (out of scope of code; record outcome in `audit/`).

---

## Self-Review (executed)

**Spec coverage** — every finding from both audit passes maps to a phase (see "Finding-to-phase map" at the top). N20 lands in docs/operations.md as governance, not code. MCP05 explicitly marked N/A.

**Placeholder scan** — searched for "TBD", "TODO", "implement later", "add appropriate", "similar to". None present. The few `<DIGEST>` placeholders in Task 0.2 are instructions to the engineer to substitute real values they capture in the prior step; they are not unspecified code.

**Type consistency** — `OboCacheKey`, `IPublicBaseUrlAccessor`, `EntraIdOptions`, `ProxyOptions`, `DownstreamServerOptions`, `EgressAllowlist`, `AuditLog`, `ToolPolicyService`, `OboExchangeException`, `IDiscoveryContext`, `DownstreamAuthorizationFilter`, `RedirectUriValidator`, `PkceValidator` — each defined once and referenced consistently across phases.

**Sequencing check** — Phase 2 deliberately precedes Phase 8 because its outcome determines Phase 8's shape. Phase 0 + 1 precede everything because TDD + CI + lockfile are foundational. Phase 16 (docs) trails because README content depends on Phase 2's finding.

---

## Execution Handoff

Plan saved to `docs/superpowers/plans/2026-05-21-entra-mcp-proxy-remediation.md`. Two execution options:

**1. Subagent-Driven (recommended)** — I dispatch a fresh subagent per task, review between tasks, fast iteration. Best for a plan this size: keeps each subagent's context tight on one task, lets me catch drift early.

**2. Inline Execution** — Execute tasks in this session using executing-plans, with review checkpoints between phases. Slower per-task but everything stays in one transcript.

**Which approach?**

If you want me to start, I would suggest beginning with Phase 0 + 1 + 2 as the first concrete chunk: those three phases unblock everything else and the SDK transport probe (Phase 2) gives us the answer to the single biggest open architectural question (per-request vs per-session in the MCP SDK). Once that result is in, I can revise Phase 8 (and possibly tighten Phase 7) before continuing.
