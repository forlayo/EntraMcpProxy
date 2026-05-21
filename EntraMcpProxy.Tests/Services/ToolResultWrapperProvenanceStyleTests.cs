using System.Collections.Generic;
using System.Linq;
using EntraMcpProxy.Configuration;
using EntraMcpProxy.Services;
using FluentAssertions;
using Microsoft.Extensions.Options;
using ModelContextProtocol.Protocol;
using Xunit;

namespace EntraMcpProxy.Tests.Services;

/// <summary>
/// Tests for the configurable ProvenanceStyle in ToolResultWrapper
/// (Block A compat — configurable tool result wrapping).
///
/// Three styles:
///   Full   — wraps in &lt;downstream-content source=... tool=...&gt; XML tags (existing default).
///   Inline — prepends [from {prefix}:{tool}]\n inline marker.
///   Off    — passes content through unchanged.
///
/// All styles must respect MaxBytes truncation.
/// </summary>
public class ToolResultWrapperProvenanceStyleTests
{
    private static ToolResultWrapper Build(
        ProvenanceStyle style,
        int maxBytes = 256 * 1024) =>
        new(Options.Create(new ProxyOptions
        {
            PublicBaseUrl       = "https://proxy.example.com",
            AllowedRedirectUris = new() { "https://claude.ai/callback" },
            EgressAllowlist     = new() { "dev.azure.com" },
            ToolResult = new ProxyOptions.ToolResultOptions
            {
                MaxBytes   = maxBytes,
                Provenance = style,
            },
        }));

    private static CallToolResult OneTextBlock(string text) =>
        new()
        {
            Content = new List<ContentBlock> { new TextContentBlock { Text = text } },
            IsError = false,
        };

    // -----------------------------------------------------------------------
    // Full style — existing behavior must be preserved
    // -----------------------------------------------------------------------

    [Fact]
    public void Full_wraps_with_XML_downstream_content_tag()
    {
        var wrapped = Build(ProvenanceStyle.Full)
            .Wrap(OneTextBlock("pong"), "azdevops", "ping");

        var text = ((TextContentBlock)wrapped.Content[0]).Text!;
        text.Should().StartWith("<downstream-content source=\"azdevops\" tool=\"ping\">");
        text.Should().Contain("pong");
        text.Should().EndWith("</downstream-content>");
    }

    [Fact]
    public void Full_includes_source_and_tool_attributes()
    {
        var text = ((TextContentBlock)Build(ProvenanceStyle.Full)
            .Wrap(OneTextBlock("x"), "svc", "list_items")
            .Content[0]).Text!;

        text.Should().Contain("source=\"svc\"");
        text.Should().Contain("tool=\"list_items\"");
    }

    [Fact]
    public void Full_truncates_oversized_content_with_marker_inside_close_tag()
    {
        var huge = new string('A', 10_000);
        var text = ((TextContentBlock)Build(ProvenanceStyle.Full, maxBytes: 500)
            .Wrap(OneTextBlock(huge), "svc", "big")
            .Content[0]).Text!;

        text.Should().Contain("[truncated]");
        text.Should().EndWith("</downstream-content>");
        text.Length.Should().BeLessThan(huge.Length + 200);
    }

    // -----------------------------------------------------------------------
    // Inline style
    // -----------------------------------------------------------------------

    [Fact]
    public void Inline_prepends_bracket_marker()
    {
        var text = ((TextContentBlock)Build(ProvenanceStyle.Inline)
            .Wrap(OneTextBlock("hello world"), "azdevops", "get_item")
            .Content[0]).Text!;

        text.Should().StartWith("[from azdevops:get_item]\n");
        text.Should().Contain("hello world");
        text.Should().NotContain("<downstream-content");
        text.Should().NotContain("</downstream-content>");
    }

    [Fact]
    public void Inline_marker_uses_prefix_and_toolname()
    {
        var text = ((TextContentBlock)Build(ProvenanceStyle.Inline)
            .Wrap(OneTextBlock("data"), "myprefix", "my_tool")
            .Content[0]).Text!;

        text.Should().StartWith("[from myprefix:my_tool]\n");
    }

    [Fact]
    public void Inline_truncates_oversized_content_with_marker()
    {
        var huge = new string('B', 10_000);
        var text = ((TextContentBlock)Build(ProvenanceStyle.Inline, maxBytes: 200)
            .Wrap(OneTextBlock(huge), "svc", "tool")
            .Content[0]).Text!;

        text.Should().Contain("[truncated]");
        text.Length.Should().BeLessThan(huge.Length + 50);
        // Must still have the inline marker prefix
        text.Should().StartWith("[from svc:tool]\n");
    }

    // -----------------------------------------------------------------------
    // Off style — pass through unchanged
    // -----------------------------------------------------------------------

    [Fact]
    public void Off_passes_content_through_unchanged()
    {
        const string original = "raw content — no wrapping";
        var text = ((TextContentBlock)Build(ProvenanceStyle.Off)
            .Wrap(OneTextBlock(original), "svc", "tool")
            .Content[0]).Text!;

        text.Should().Be(original);
        text.Should().NotContain("<downstream-content");
        text.Should().NotContain("[from ");
    }

    [Fact]
    public void Off_truncates_oversized_content()
    {
        var huge = new string('C', 10_000);
        var text = ((TextContentBlock)Build(ProvenanceStyle.Off, maxBytes: 300)
            .Wrap(OneTextBlock(huge), "svc", "tool")
            .Content[0]).Text!;

        text.Should().Contain("[truncated]");
        text.Length.Should().BeLessThan(huge.Length);
        // No XML tags, no inline marker
        text.Should().NotContain("<downstream-content");
        text.Should().NotContain("[from ");
    }

    // -----------------------------------------------------------------------
    // Default style is Full (existing integration tests continue to work)
    // -----------------------------------------------------------------------

    [Fact]
    public void Default_Provenance_is_Full()
    {
        var opts = new ProxyOptions.ToolResultOptions();
        opts.Provenance.Should().Be(ProvenanceStyle.Full);
    }

    // -----------------------------------------------------------------------
    // IsError flag is preserved across all styles
    // -----------------------------------------------------------------------

    [Theory]
    [InlineData(ProvenanceStyle.Full)]
    [InlineData(ProvenanceStyle.Inline)]
    [InlineData(ProvenanceStyle.Off)]
    public void IsError_flag_is_preserved(ProvenanceStyle style)
    {
        var input = new CallToolResult
        {
            Content = new List<ContentBlock> { new TextContentBlock { Text = "err" } },
            IsError = true,
        };
        Build(style).Wrap(input, "svc", "tool").IsError.Should().BeTrue();
    }
}
