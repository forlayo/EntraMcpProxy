namespace EntraMcpProxy.Auth;

/// <summary>
/// Thrown when an OBO token exchange against Entra fails. The exception's
/// <see cref="Exception.Message"/> is intentionally generic and safe to surface to
/// clients via GlobalExceptionHandler. Raw Entra response details (which
/// may include AADSTS codes, tenant hints, or scope information) live
/// only in <see cref="InnerEntraBody"/>, which is consumed by structured
/// logging but never echoed to clients.
/// </summary>
public sealed class OboExchangeException : Exception
{
    public string? InnerEntraBody { get; }

    public OboExchangeException(string message, string? innerEntraBody = null)
        : base(message)
    {
        InnerEntraBody = innerEntraBody;
    }
}
