namespace EntraMcpProxy.Auth;

/// <summary>
/// AsyncLocal scope that opts the current async call chain into the SP
/// (client_credentials) discovery path in <see cref="EntraIdOBOHandler"/>.
///
/// By default, OBO exchange requires a real user principal in HttpContext. Startup
/// and refresh code (tool discovery) runs without a user context, so it must
/// explicitly declare itself a discovery caller via <see cref="Enter"/>.
///
/// This prevents a silent SP-token fallback from leaking into user request paths
/// (audit finding H6).
/// </summary>
public static class DiscoveryContext
{
    private static readonly AsyncLocal<bool> _isDiscovery = new();

    /// <summary>
    /// Returns <c>true</c> when the current async context is inside a
    /// <see cref="Enter"/> scope.
    /// </summary>
    public static bool IsActive => _isDiscovery.Value;

    /// <summary>
    /// Enters discovery scope. Dispose the returned handle to leave.
    /// </summary>
    public static IDisposable Enter()
    {
        _isDiscovery.Value = true;
        return new Scope();
    }

    private sealed class Scope : IDisposable
    {
        public void Dispose() => _isDiscovery.Value = false;
    }
}
