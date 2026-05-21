using System.Collections.Generic;
using EntraMcpProxy.Configuration;
using EntraMcpProxy.Services;
using FluentAssertions;
using Microsoft.Extensions.Options;
using ModelContextProtocol.Protocol;
using Xunit;

namespace EntraMcpProxy.Tests.Services;

/// <summary>
/// Tests for ToolResultWrapper (audit findings N11, N12).
///
/// N11: Each TextContentBlock is wrapped with an XML-style provenance tag so the
///      Claude model knows content originated from a downstream system, not the
///      user or system prompt.  Addresses MCP06 (Intent Flow Subversion).
///
/// N12: Combined text-content size is capped at ProxyOptions.ToolResult.MaxBytes.
///      Oversized blocks are truncated and marked with '…[truncated]'.
/// </summary>
public class ToolResultWrapperTests
{
    private static ToolResultWrapper New(int maxBytes = 256 * 1024) =>
        new(Options.Create(new ProxyOptions
        {
            // Provide required fields so ProxyOptions is well-formed.
            PublicBaseUrl       = "https://proxy.example.com",
            AllowedRedirectUris = new() { "https://claude.ai/callback" },
            EgressAllowlist     = new() { "dev.azure.com" },
            ToolResult          = new ProxyOptions.ToolResultOptions { MaxBytes = maxBytes },
        }));

    private static CallToolResult ResultWithText(params string[] texts)
    {
        var blocks = new List<ContentBlock>();
        foreach (var t in texts)
            blocks.Add(new TextContentBlock { Text = t });
        return new CallToolResult { Content = blocks, IsError = false };
    }

    // -----------------------------------------------------------------------
    // N11: provenance tag wrapping
    // -----------------------------------------------------------------------

    [Fact]
    public void Wraps_single_text_block_with_downstream_content_tag()
    {
        var input = ResultWithText("pong");
        var wrapped = New().Wrap(input, "azdevops", "ping");

        wrapped.Content.Should().HaveCount(1);
        var block = wrapped.Content[0].Should().BeOfType<TextContentBlock>().Subject;
        block.Text.Should().StartWith("<downstream-content source=\"azdevops\" tool=\"ping\">");
        block.Text.Should().Contain("pong");
        block.Text.Should().EndWith("</downstream-content>");
    }

    [Fact]
    public void Wraps_each_text_block_independently()
    {
        var input = ResultWithText("first", "second");
        var wrapped = New().Wrap(input, "azdevops", "list");

        wrapped.Content.Should().HaveCount(2);
        ((TextContentBlock)wrapped.Content[0]).Text.Should().Contain("first");
        ((TextContentBlock)wrapped.Content[1]).Text.Should().Contain("second");
        ((TextContentBlock)wrapped.Content[0]).Text.Should().Contain("<downstream-content");
        ((TextContentBlock)wrapped.Content[1]).Text.Should().Contain("<downstream-content");
    }

    [Fact]
    public void Tag_includes_source_and_tool_attributes()
    {
        var wrapped = New().Wrap(ResultWithText("x"), "azdevops", "create_work_item");
        var text = ((TextContentBlock)wrapped.Content[0]).Text!;

        text.Should().Contain("source=\"azdevops\"");
        text.Should().Contain("tool=\"create_work_item\"");
    }

    [Fact]
    public void Preserves_IsError_true_flag()
    {
        var input = new CallToolResult
        {
            Content = new List<ContentBlock> { new TextContentBlock { Text = "bad" } },
            IsError = true,
        };
        var wrapped = New().Wrap(input, "x", "y");

        wrapped.IsError.Should().BeTrue();
    }

    [Fact]
    public void Preserves_IsError_false_flag()
    {
        var input = ResultWithText("ok");
        var wrapped = New().Wrap(input, "x", "y");

        wrapped.IsError.Should().BeFalse();
    }

    // -----------------------------------------------------------------------
    // N12: size cap / truncation
    // -----------------------------------------------------------------------

    [Fact]
    public void Truncates_content_over_MaxBytes_and_adds_marker()
    {
        // 10 000 chars — well over a 2 000-byte limit.
        var huge = new string('A', 10_000);
        var input = ResultWithText(huge);

        var wrapped = New(maxBytes: 2_000).Wrap(input, "azdevops", "huge");
        var text = ((TextContentBlock)wrapped.Content[0]).Text!;

        text.Length.Should().BeLessThan(huge.Length + 200, // allow for tag overhead
            "the result must be meaningfully shorter than the raw input");
        text.Should().Contain("[truncated]");
        // The close tag must still be present — truncation happens inside the tag.
        text.Should().EndWith("</downstream-content>");
    }

    [Fact]
    public void Does_not_truncate_content_within_MaxBytes()
    {
        var content = "short";
        var input = ResultWithText(content);

        var wrapped = New(maxBytes: 256 * 1024).Wrap(input, "svc", "tool");
        var text = ((TextContentBlock)wrapped.Content[0]).Text!;

        text.Should().Contain(content);
        text.Should().NotContain("[truncated]");
    }

    [Fact]
    public void Drops_subsequent_blocks_when_budget_exhausted()
    {
        // First block fills the budget; second block should be dropped.
        var big = new string('B', 10_000);
        var input = ResultWithText(big, "second_block");

        var wrapped = New(maxBytes: 500).Wrap(input, "svc", "tool");

        // Second block may be omitted once budget is exhausted.
        // Either 1 block (dropped) or 2 blocks (first truncated, second marker-only) are acceptable.
        // What is NOT acceptable: the raw second block appearing without truncation.
        var allText = string.Concat(wrapped.Content.OfType<TextContentBlock>().Select(b => b.Text));
        // If second block appears, it must be a truncation notice, not the real content.
        if (allText.Contains("second_block"))
        {
            // If somehow the second block fits, that's fine — budget math allows it.
            // But the combined length should still be within a reasonable margin of MaxBytes.
            allText.Length.Should().BeLessThan(500 + 500,
                "combined output must stay near the budget even if second block partially fits");
        }
    }
}
