using System.Collections.Concurrent;
using System.Collections.Generic;
using EntraMcpProxy.Auth;
using FluentAssertions;
using Xunit;

namespace EntraMcpProxy.Tests.Auth;

public class OboCacheKeyTests
{
    [Fact]
    public void Two_users_with_same_scope_produce_different_keys()
    {
        var alice = OboCacheKey.From(oid: "alice", tid: "T", aud: "A", scope: "S");
        var bob   = OboCacheKey.From(oid: "bob",   tid: "T", aud: "A", scope: "S");
        alice.Should().NotBe(bob);
        alice.GetHashCode().Should().NotBe(bob.GetHashCode(),
            "the structural hash should reflect oid differences");
    }

    [Fact]
    public void Same_user_same_scope_produces_identical_keys()
    {
        var k1 = OboCacheKey.From("alice", "T", "A", "S");
        var k2 = OboCacheKey.From("alice", "T", "A", "S");
        k1.Should().Be(k2);
        k1.GetHashCode().Should().Be(k2.GetHashCode());
    }

    [Fact]
    public void Different_tenant_yields_different_key()
    {
        OboCacheKey.From("alice", "T1", "A", "S")
            .Should().NotBe(OboCacheKey.From("alice", "T2", "A", "S"));
    }

    [Fact]
    public void Different_audience_yields_different_key()
    {
        OboCacheKey.From("alice", "T", "A1", "S")
            .Should().NotBe(OboCacheKey.From("alice", "T", "A2", "S"));
    }

    [Fact]
    public void Different_scope_yields_different_key()
    {
        OboCacheKey.From("alice", "T", "A", "S1")
            .Should().NotBe(OboCacheKey.From("alice", "T", "A", "S2"));
    }

    [Fact]
    public void Comparison_is_case_sensitive()
    {
        // OIDs are case-sensitive GUIDs in practice. Be strict.
        OboCacheKey.From("alice", "T", "A", "S")
            .Should().NotBe(OboCacheKey.From("ALICE", "T", "A", "S"));
    }

    [Fact]
    public void Works_as_ConcurrentDictionary_key()
    {
        var dict = new ConcurrentDictionary<OboCacheKey, string>();
        var aliceKey = OboCacheKey.From("alice", "T", "A", "S");
        var bobKey   = OboCacheKey.From("bob",   "T", "A", "S");

        dict[aliceKey] = "alice-token";
        dict[bobKey]   = "bob-token";

        dict[aliceKey].Should().Be("alice-token");
        dict[bobKey].Should().Be("bob-token");
        dict.Count.Should().Be(2);
    }

    [Fact]
    public void Equality_is_value_based_across_instances()
    {
        // Same logical key constructed independently should be considered equal,
        // satisfying the contract a dictionary needs.
        var a = OboCacheKey.From("alice", "T", "A", "S");
        var b = OboCacheKey.From(string.Concat("ali", "ce"), "T", "A", "S");
        a.Equals(b).Should().BeTrue();
        (a == b).Should().BeTrue();
    }

    [Fact]
    public void ToString_does_not_leak_full_oid()
    {
        // ToString gets logged. The full oid is PII / identity. Make the type's
        // string form non-leaky — either redact or show only a fingerprint.
        var key = OboCacheKey.From(
            "00000000-1111-2222-3333-444444444444",
            "00000000-aaaa-bbbb-cccc-dddddddddddd",
            "api://x", "scope");
        var s = key.ToString();
        s.Should().NotContain("00000000-1111-2222-3333-444444444444");
    }
}
