using FluentAssertions;
using Xunit;

namespace EntraMcpProxy.Tests;

public class SmokeTest
{
    [Fact]
    public void True_is_true() => true.Should().BeTrue();
}
