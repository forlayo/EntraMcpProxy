using System.Net.Http;
using System.Net.Http.Headers;
using System.Text;
using System.Threading.Tasks;
using FluentAssertions;
using Xunit;

namespace EntraMcpProxy.IntegrationTests.Fixtures;

public class FakeDownstreamMcpTests
{
    [Fact]
    public async Task Records_Authorization_header_on_initialize()
    {
        await using var dn = new FakeDownstreamMcp();
        using var http = new HttpClient();
        http.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", "alice-token");

        var resp = await http.PostAsync(dn.Url,
            new StringContent("""{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}""",
                Encoding.UTF8, "application/json"));

        resp.IsSuccessStatusCode.Should().BeTrue();
        dn.RecordedCalls.Should().ContainSingle();
        dn.RecordedCalls[0].Method.Should().Be("initialize");
        dn.RecordedCalls[0].Authorization.Should().Be("Bearer alice-token");
    }

    [Fact]
    public async Task Discriminates_between_users_in_recorded_calls()
    {
        await using var dn = new FakeDownstreamMcp();
        using var http = new HttpClient();

        async Task Call(string token, string method)
        {
            using var req = new HttpRequestMessage(HttpMethod.Post, dn.Url)
            {
                Content = new StringContent(
                    $$$"""{"jsonrpc":"2.0","id":1,"method":"{{{method}}}","params":{}}""",
                    Encoding.UTF8, "application/json"),
            };
            req.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);
            (await http.SendAsync(req)).IsSuccessStatusCode.Should().BeTrue();
        }

        await Call("alice-token", "tools/list");
        await Call("bob-token",   "tools/call");

        dn.RecordedCalls.Should().HaveCount(2);
        dn.RecordedCalls[0].Authorization.Should().Be("Bearer alice-token");
        dn.RecordedCalls[0].Method.Should().Be("tools/list");
        dn.RecordedCalls[1].Authorization.Should().Be("Bearer bob-token");
        dn.RecordedCalls[1].Method.Should().Be("tools/call");
    }

    [Fact]
    public async Task ToolsList_returns_default_ping_tool()
    {
        await using var dn = new FakeDownstreamMcp();
        using var http = new HttpClient();

        var resp = await http.PostAsync(dn.Url,
            new StringContent("""{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}""",
                Encoding.UTF8, "application/json"));

        string body = await resp.Content.ReadAsStringAsync();
        body.Should().Contain("\"ping\"");
        body.Should().Contain("Returns pong.");
    }

    [Fact]
    public async Task ToolsList_returns_custom_tools_when_reconfigured()
    {
        await using var dn = new FakeDownstreamMcp();
        dn.Tools.Clear();
        dn.Tools.Add(new FakeTool("custom_tool", "Custom description.", """{"type":"object"}"""));

        using var http = new HttpClient();
        var resp = await http.PostAsync(dn.Url,
            new StringContent("""{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}""",
                Encoding.UTF8, "application/json"));

        string body = await resp.Content.ReadAsStringAsync();
        body.Should().Contain("\"custom_tool\"");
        body.Should().NotContain("\"ping\"");
    }
}
