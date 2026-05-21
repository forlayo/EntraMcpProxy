using System;
using System.Security.Cryptography;
using System.Text;

namespace EntraMcpProxy.Auth;

/// <summary>
/// Collision-free cache key for OBO token caching, derived from the
/// validated caller's <c>oid</c>, <c>tid</c>, the downstream <c>aud</c>,
/// and the requested <c>scope</c>.
///
/// Closes audit finding C1 (cross-user OBO token leak via the previous
/// implementation's reliance on <see cref="string.GetHashCode"/> of the
/// raw assertion — 32-bit collisions occur naturally at population
/// scales typical of corporate Entra tenants).
///
/// Equality is value-based and ordinal/case-sensitive over the four
/// component strings. <see cref="GetHashCode"/> uses SHA-256 truncated
/// to <see cref="int"/> for a much wider hash dispersion than the
/// default record-struct combine — exhausting the int space still
/// happens only at √(2^32) entries, but two cache entries that hash
/// to the same int do NOT collide because <see cref="Equals"/> is
/// distinct.
///
/// <see cref="ToString"/> intentionally redacts the full oid so log
/// lines that include this key do not leak identity GUIDs.
/// </summary>
public readonly struct OboCacheKey : IEquatable<OboCacheKey>
{
    public string Oid   { get; }
    public string Tid   { get; }
    public string Aud   { get; }
    public string Scope { get; }

    private OboCacheKey(string oid, string tid, string aud, string scope)
    {
        Oid = oid; Tid = tid; Aud = aud; Scope = scope;
    }

    public static OboCacheKey From(string oid, string tid, string aud, string scope)
        => new(oid, tid, aud, scope);

    public bool Equals(OboCacheKey other) =>
        string.Equals(Oid,   other.Oid,   StringComparison.Ordinal) &&
        string.Equals(Tid,   other.Tid,   StringComparison.Ordinal) &&
        string.Equals(Aud,   other.Aud,   StringComparison.Ordinal) &&
        string.Equals(Scope, other.Scope, StringComparison.Ordinal);

    public override bool Equals(object? obj) => obj is OboCacheKey other && Equals(other);

    public override int GetHashCode()
    {
        // SHA-256 over the canonical composition. The first 4 bytes
        // form the int hash. Equality is still authoritative — a
        // 32-bit collision does not produce a false positive.
        Span<byte> payload = stackalloc byte[4 * 1024];
        int written = 0;
        written += Encoding.UTF8.GetBytes(Oid,   payload[written..]);
        payload[written++] = (byte)'|';
        written += Encoding.UTF8.GetBytes(Tid,   payload[written..]);
        payload[written++] = (byte)'|';
        written += Encoding.UTF8.GetBytes(Aud,   payload[written..]);
        payload[written++] = (byte)'|';
        written += Encoding.UTF8.GetBytes(Scope, payload[written..]);

        Span<byte> digest = stackalloc byte[32];
        SHA256.HashData(payload[..written], digest);
        return BitConverter.ToInt32(digest[..4]);
    }

    public static bool operator ==(OboCacheKey a, OboCacheKey b) => a.Equals(b);
    public static bool operator !=(OboCacheKey a, OboCacheKey b) => !a.Equals(b);

    /// <summary>
    /// Redacted form safe to include in logs.
    /// </summary>
    public override string ToString()
    {
        static string Fingerprint(string s)
        {
            if (string.IsNullOrEmpty(s)) return "(empty)";
            // First 2 bytes (4 hex chars) of SHA-256 — enough to disambiguate
            // entries in a log without leaking the full GUID.
            Span<byte> digest = stackalloc byte[32];
            SHA256.HashData(Encoding.UTF8.GetBytes(s), digest);
            return Convert.ToHexString(digest[..2]).ToLowerInvariant();
        }
        return $"oid:{Fingerprint(Oid)}|tid:{Fingerprint(Tid)}|aud:{Aud}|scope:{Scope}";
    }
}
