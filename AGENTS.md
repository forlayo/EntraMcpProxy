# Repository Guidelines

## Project Structure & Module Organization

EntraMcpProxy is a .NET 10 ASP.NET Core MCP/OAuth proxy. `Program.cs` contains app bootstrap and HTTP endpoints. Core code is split by responsibility: `Auth/` for Entra ID, PKCE, redirect, and OBO logic; `Configuration/` for options and validators; `Infrastructure/` for middleware, health checks, audit, metrics, and egress controls; `Services/` for downstream MCP clients, tool registry, policy, and result wrapping.

Tests live in `EntraMcpProxy.Tests/` for unit coverage, `EntraMcpProxy.IntegrationTests/` for in-memory and WireMock scenarios, and `EntraMcpProxy.E2ETests/` for Docker/Testcontainers flows. Docs are under `docs/`, Azure Container Apps assets under `iac/`, monitoring under `monitoring/`, and standalone NBomber load tests under `loadtests/EntraMcpProxy.LoadTests/`.

## Build, Test, and Development Commands

- `dotnet restore --locked-mode`: restores packages using lock files.
- `dotnet build --no-restore --configuration Release -warnaserror`: matches CI build strictness.
- `dotnet test --no-build --configuration Release`: runs solution tests after Release build.
- `dotnet test EntraMcpProxy.Tests`: runs unit tests only.
- `dotnet test EntraMcpProxy.IntegrationTests`: runs integration tests.
- `dotnet test EntraMcpProxy.E2ETests`: runs Docker-based E2E tests.
- `dotnet run`: starts the proxy.
- `docker build -t entra-mcp-proxy .`: builds the image.
- `cd loadtests/EntraMcpProxy.LoadTests && PROXY_BASE_URL=https://example dotnet run`: runs load scenarios.

## Coding Style & Naming Conventions

Use C# with nullable references and implicit usings enabled. Warnings are errors via `Directory.Build.props`. Keep 4-space indentation, file-scoped namespaces, PascalCase public types and members, `_camelCase` private fields, and concise XML/comments only where behavior is not obvious. Package versions are centralized in `Directory.Packages.props`; do not add versions directly in project files.

## Testing Guidelines

The test stack is xUnit, FluentAssertions, NSubstitute, WireMock.Net, and Testcontainers. Mirror source folders in test projects where practical. Name test classes `<TypeUnderTest>Tests`; use descriptive test methods such as `Rejects_missing_challenge` or `<Scenario>_<Condition>_<Expectation>`. Add regression tests for security-sensitive OAuth, OBO, egress, audit, and tool-routing changes.

## Commit & Pull Request Guidelines

Git history uses Conventional Commits, for example `fix(iac): ...`, `feat(discovery): ...`, `test(e2e): ...`, and `docs: ...`. Keep commits focused and scoped. PRs should summarize behavior changes, list validation commands run, link related issues or audit findings, and call out config, secret, deployment, or security implications. Include screenshots only for UI or dashboard changes.

## Security & Configuration Tips

Never commit secrets. Put client secrets in environment variables, Kubernetes Secrets, or Key Vault. Keep `appsettings.json` limited to non-secret defaults, and use double-underscore environment variable names such as `DownstreamServers__0__OBO__ClientSecret`. Run `dotnet list package --vulnerable --include-transitive` before security-sensitive releases; CI blocks High and Critical advisories.
