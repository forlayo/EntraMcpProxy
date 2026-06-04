using EntraMcpProxy.E2ETests.Fixtures;
using Xunit;

namespace EntraMcpProxy.E2ETests;

/// <summary>
/// Defines a single xUnit test collection for all E2E container tests.
///
/// E2E tests boot real Docker containers (proxy image build, WireMock network,
/// etc.) and must run serially to avoid two tests trying to write the same
/// Testcontainers Docker image tar file simultaneously.
///
/// Any test class decorated with [Collection("E2E")] will share this collection
/// and execute sequentially.
/// </summary>
[CollectionDefinition("E2E", DisableParallelization = true)]
public sealed class E2ETestCollection : ICollectionFixture<ProxyContainerFixture> { }
