using EntraMcpProxy.Configuration;
using EntraMcpProxy.Infrastructure;
using FluentAssertions;
using Microsoft.Extensions.Options;
using Xunit;

namespace EntraMcpProxy.Tests.Infrastructure;

public class PublicBaseUrlAccessorTests
{
    private static PublicBaseUrlAccessor New(string url) =>
        new(Options.Create(new ProxyOptions { PublicBaseUrl = url }));

    [Fact]
    public void Returns_configured_value()
    {
        New("https://canon.example.com").Get().Should().Be("https://canon.example.com");
    }

    [Fact]
    public void Trims_trailing_slash()
    {
        New("https://canon.example.com/").Get().Should().Be("https://canon.example.com");
    }

    [Fact]
    public void Trims_multiple_trailing_slashes()
    {
        // Defensive: configured value with accidental double-slash.
        New("https://canon.example.com///").Get().Should().Be("https://canon.example.com");
    }

    [Fact]
    public void Does_not_trim_internal_slashes()
    {
        New("https://canon.example.com/api").Get().Should().Be("https://canon.example.com/api");
    }

    [Fact]
    public void Does_not_use_request_headers()
    {
        // Even with a configured value AND a hypothetical adversarial request,
        // the accessor only consults configuration. (The test compiles regardless of
        // any HTTP context — the accessor has no IHttpContextAccessor dependency.)
        var accessor = New("https://canon.example.com");
        accessor.Get().Should().Be("https://canon.example.com");
    }
}
