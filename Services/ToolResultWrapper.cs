using System.Collections.Generic;
using EntraMcpProxy.Configuration;
using Microsoft.Extensions.Options;
using ModelContextProtocol.Protocol;

namespace EntraMcpProxy.Services;

/// <summary>
/// Wraps downstream MCP tool-call results with provenance tags and enforces a
/// per-call size cap.
///
/// N11 (tool result poisoning defense): every <see cref="TextContentBlock"/> is
/// wrapped in a single XML-style tag before being returned to the MCP server:
///
///   &lt;downstream-content source="{prefix}" tool="{toolName}"&gt;
///   {original text}
///   &lt;/downstream-content&gt;
///
/// This gives the Claude model a provenance signal so prompt-injection payloads
/// embedded in user-writable downstream content (work-item descriptions, PR
/// comments, build logs, etc.) cannot pose as authoritative instructions from
/// the user or system prompt.
///
/// Non-text content blocks (images, embedded resources) pass through unchanged
/// — they are not a prompt-injection vector.
///
/// N12 (response size budget): the combined size of all text blocks is capped
/// at <see cref="ProxyOptions.ToolResultOptions.MaxBytes"/>. If the budget is
/// exhausted, the last oversized block is truncated and a "…[truncated]" marker
/// is appended inside the close tag. Subsequent blocks are dropped. This
/// prevents a runaway or malicious downstream from flooding the model's context.
/// </summary>
public sealed class ToolResultWrapper
{
    private readonly IOptions<ProxyOptions> _options;

    public ToolResultWrapper(IOptions<ProxyOptions> options)
    {
        _options = options;
    }

    /// <summary>
    /// Returns a new <see cref="CallToolResult"/> whose text blocks are wrapped
    /// with provenance tags and whose combined text size is capped at MaxBytes.
    /// The original <paramref name="original"/> is not mutated.
    /// </summary>
    public CallToolResult Wrap(CallToolResult original, string prefix, string toolName)
    {
        int maxBytes = _options.Value.ToolResult.MaxBytes;
        var newBlocks = new List<ContentBlock>(original.Content.Count);
        int runningTotal = 0;

        foreach (var block in original.Content)
        {
            if (block is TextContentBlock text)
            {
                var (wrapped, blockSize) = WrapTextBlock(
                    text.Text ?? "",
                    prefix,
                    toolName,
                    remainingBudget: maxBytes - runningTotal);

                runningTotal += blockSize;
                newBlocks.Add(new TextContentBlock { Text = wrapped });
            }
            else
            {
                // Non-text content (images, audio, embedded resources) — pass through.
                // Not a prompt-injection vector.
                newBlocks.Add(block);
            }

            if (runningTotal >= maxBytes)
            {
                // Budget exhausted — drop any remaining blocks.
                break;
            }
        }

        return new CallToolResult
        {
            Content = newBlocks,
            IsError = original.IsError,
        };
    }

    private static (string Wrapped, int Size) WrapTextBlock(
        string text,
        string prefix,
        string toolName,
        int remainingBudget)
    {
        string openTag  = $"<downstream-content source=\"{prefix}\" tool=\"{toolName}\">";
        string closeTag = "</downstream-content>";
        // Overhead = openTag + newline + newline + closeTag
        int overhead = openTag.Length + 1 + 1 + closeTag.Length;

        if (remainingBudget <= overhead)
        {
            // No room even for the wrapper tags — emit a minimal truncation notice.
            const string notice = "[truncated: budget exhausted]";
            var minimal = $"{openTag}\n{notice}\n{closeTag}";
            return (minimal, minimal.Length);
        }

        int textBudget = remainingBudget - overhead;
        if (text.Length <= textBudget)
        {
            var full = $"{openTag}\n{text}\n{closeTag}";
            return (full, full.Length);
        }
        else
        {
            const string marker = "…[truncated]";  // '…[truncated]'
            // Ensure the truncated slice + marker fits in textBudget.
            int sliceLength = textBudget - marker.Length;
            if (sliceLength < 0) sliceLength = 0;
            var truncated = text[..sliceLength] + marker;
            var full = $"{openTag}\n{truncated}\n{closeTag}";
            return (full, full.Length);
        }
    }
}
