using System;
using System.Threading.Tasks;
using EntraMcpProxy.IntegrationTests.Fixtures;
using FluentAssertions;
using Microsoft.AspNetCore.Hosting;
using Microsoft.Extensions.Options;
using Xunit;

namespace EntraMcpProxy.IntegrationTests.Startup;

public class ProductionConfigGuardTests
{
    [Fact]
    public void Production_env_with_RequireHttpsMetadata_false_throws_at_startup()
    {
        // ProxyAppFactory defaults to environment "IntegrationTest" with HTTPS off.
        // Override the environment to Production and assert the guard fires.
        var factory = new ProductionFactory
        {
            RequireHttps = false,
        };

        // The guard throws InvalidOperationException which WebApplicationFactory
        // may wrap in another exception — walk the chain to find it.
        // ThrowsAny accepts derived types (unlike Throws which is exact-match).
        var ex = Assert.ThrowsAny<Exception>(() => factory.CreateClient());

        // Walk the entire exception chain looking for the guard message.
        var found = ContainsGuardMessage(ex, "RequireHttpsMetadata");
        found.Should().BeTrue(
            $"Expected 'RequireHttpsMetadata' in exception chain but got: {ex}");
    }

    [Fact]
    public async Task Production_env_with_RequireHttpsMetadata_true_boots_successfully()
    {
        await using var factory = new ProductionFactory
        {
            RequireHttps = true,
            // Production env requires a real-looking authority; the proxy will try to
            // fetch OIDC metadata at first request, but startup itself should succeed.
        };

        // Boot test: just instantiating CreateClient runs the host through startup
        // validation. If the guard wrongly fires here, this will throw.
        using var client = factory.CreateClient();
        client.Should().NotBeNull();
    }

    /// <summary>
    /// Recursively walks an exception chain (including AggregateException inner exceptions)
    /// looking for <paramref name="fragment"/> in the Message of any node.
    /// </summary>
    private static bool ContainsGuardMessage(Exception? ex, string fragment)
    {
        while (ex != null)
        {
            if (ex.Message.Contains(fragment, StringComparison.OrdinalIgnoreCase))
                return true;

            // Also check inner exceptions of AggregateException
            if (ex is AggregateException agg)
            {
                foreach (var inner in agg.InnerExceptions)
                {
                    if (ContainsGuardMessage(inner, fragment))
                        return true;
                }
            }

            ex = ex.InnerException;
        }
        return false;
    }

    private sealed class ProductionFactory : ProxyAppFactory
    {
        protected override void ConfigureWebHost(IWebHostBuilder builder)
        {
            // Re-use the base ConfigureWebHost (in-memory config keys) but override env.
            base.ConfigureWebHost(builder);
            builder.UseEnvironment("Production");
        }
    }
}
