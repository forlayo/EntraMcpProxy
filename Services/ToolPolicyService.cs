using System;
using System.Text.Json;
using Microsoft.Extensions.Logging;
using ModelContextProtocol.Protocol;

namespace EntraMcpProxy.Services;

/// <summary>
/// Sanitizes / annotates tool metadata from downstream MCP servers before
/// it is published to claude.ai (and ultimately the Claude model).
///
/// Audit finding N5 (MCP03 Tool Poisoning): tool descriptions, names,
/// and schemas from a compromised downstream can carry adversarial
/// content. The defenses applied here are deliberately CONSERVATIVE so
/// the claude.ai connector continues to function:
///
/// - Provenance marker prepended to each Description: tells Claude
///   exactly which downstream produced this tool. Reads as "[Source:
///   downstream=prefix] ...description...". The marker is visible to
///   Claude as part of the description; the LLM has been trained to
///   weight provenance.
/// - InputSchema validator rejects schemas that contain $ref to
///   external URIs (typical injection vector) or use vendor extensions
///   ('x-' prefix). This is defense-in-depth: the MCP SDK already
///   validates schemas during deserialization, but a future SDK update
///   may relax those constraints. Schemas failing this check are
///   dropped — the tool is not registered.
/// - Description length cap prevents a downstream from sending a
///   multi-MB description that floods the context window.
///
/// We deliberately do NOT strip imperative second-person language
/// ('you must', 'always', etc.) — that would risk over-filtering
/// legitimate tool docs.
///
/// Note on SDK schema validation: as of ModelContextProtocol 0.7.0-preview.1
/// the SDK rejects empty '{}' schemas, $ref (all forms), vendor extensions
/// (x-*), and schemas exceeding system JSON depth limits at deserialization
/// time. Our policy validator is thus defense-in-depth for future SDK changes.
/// </summary>
public sealed class ToolPolicyService
{
    private const int MaxDescriptionChars = 4_000;
    private readonly ILogger<ToolPolicyService> _logger;

    public ToolPolicyService(ILogger<ToolPolicyService> logger)
    {
        _logger = logger;
    }

    /// <summary>
    /// Returns a sanitized copy of <paramref name="tool"/> annotated with
    /// downstream provenance, or null if the tool failed policy.
    /// </summary>
    public Tool? Apply(string downstreamPrefix, Tool tool)
    {
        if (string.IsNullOrWhiteSpace(tool.Name))
        {
            _logger.LogWarning("Rejecting tool from '{Prefix}' with empty name", downstreamPrefix);
            return null;
        }

        if (!CheckSchema(tool.InputSchema, out var schemaError))
        {
            _logger.LogWarning(
                "Rejecting tool '{Prefix}:{Tool}' due to schema policy violation: {Error}",
                downstreamPrefix, tool.Name, schemaError);
            return null;
        }

        var description = tool.Description ?? "";
        if (description.Length > MaxDescriptionChars)
        {
            _logger.LogInformation(
                "Truncating description for '{Prefix}:{Tool}' from {Len} to {Max} chars",
                downstreamPrefix, tool.Name, description.Length, MaxDescriptionChars);
            description = description[..MaxDescriptionChars] + "…[truncated]";
        }

        // Provenance prefix — minimal-footprint, single-line, machine-readable.
        var annotated = $"[Source: downstream={downstreamPrefix}] {description}";

        return new Tool
        {
            Name = tool.Name,
            Description = annotated,
            InputSchema = tool.InputSchema,
        };
    }

    /// <summary>
    /// Validates a raw JSON schema element for policy compliance.
    /// Exposed publicly for testability and for callers that need to validate
    /// a schema before constructing a Tool.
    /// </summary>
    public static bool CheckSchema(JsonElement schema, out string error)
    {
        error = "";
        if (schema.ValueKind == JsonValueKind.Undefined || schema.ValueKind == JsonValueKind.Null)
        {
            // Missing schema is acceptable — many tools take no args.
            return true;
        }
        if (schema.ValueKind != JsonValueKind.Object)
        {
            error = "schema must be a JSON object";
            return false;
        }
        return ValidateSchemaNode(schema, depth: 0, out error);
    }

    private static bool ValidateSchemaNode(JsonElement node, int depth, out string error)
    {
        error = "";
        if (depth > 20)
        {
            error = "schema nesting depth exceeds 20";
            return false;
        }

        if (node.ValueKind == JsonValueKind.Object)
        {
            foreach (var property in node.EnumerateObject())
            {
                // External $ref vector — common injection path.
                if (property.Name == "$ref" && property.Value.ValueKind == JsonValueKind.String)
                {
                    var refValue = property.Value.GetString() ?? "";
                    if (refValue.StartsWith("http://", StringComparison.OrdinalIgnoreCase) ||
                        refValue.StartsWith("https://", StringComparison.OrdinalIgnoreCase) ||
                        refValue.StartsWith("file://", StringComparison.OrdinalIgnoreCase))
                    {
                        error = $"external $ref not permitted: '{refValue}'";
                        return false;
                    }
                }
                // Vendor extensions — drop for safety. Common injection vector.
                if (property.Name.StartsWith("x-", StringComparison.OrdinalIgnoreCase))
                {
                    error = $"vendor extension '{property.Name}' not permitted";
                    return false;
                }

                if (!ValidateSchemaNode(property.Value, depth + 1, out error))
                {
                    return false;
                }
            }
        }
        else if (node.ValueKind == JsonValueKind.Array)
        {
            foreach (var item in node.EnumerateArray())
            {
                if (!ValidateSchemaNode(item, depth + 1, out error))
                {
                    return false;
                }
            }
        }

        return true;
    }
}
