using EntraMcpProxy.Auth;
using FluentAssertions;
using Xunit;

namespace EntraMcpProxy.Tests.Auth;

public class PkceValidatorTests
{
    private readonly PkceValidator _sut = new();

    // 43-char base64url string (valid lower bound per RFC 7636 §4.2)
    private const string ValidChallenge = "abcd1234abcd1234abcd1234abcd1234abcd1234abc";

    [Fact]
    public void Accepts_valid_S256_pair()
    {
        var result = _sut.Validate(challenge: ValidChallenge, method: "S256");
        result.IsValid.Should().BeTrue();
        result.Error.Should().BeNull();
    }

    [Fact]
    public void Rejects_missing_challenge()
    {
        var result = _sut.Validate(challenge: null, method: "S256");
        result.IsValid.Should().BeFalse();
        result.Error.Should().Contain("code_challenge");
    }

    [Fact]
    public void Rejects_empty_challenge()
    {
        var result = _sut.Validate(challenge: "", method: "S256");
        result.IsValid.Should().BeFalse();
    }

    [Fact]
    public void Rejects_whitespace_challenge()
    {
        var result = _sut.Validate(challenge: "   ", method: "S256");
        result.IsValid.Should().BeFalse();
    }

    [Fact]
    public void Rejects_missing_method()
    {
        var result = _sut.Validate(challenge: ValidChallenge, method: null);
        result.IsValid.Should().BeFalse();
        result.Error.Should().Contain("code_challenge_method");
    }

    [Theory]
    [InlineData("plain")]
    [InlineData("PLAIN")]
    [InlineData("S192")]
    [InlineData("RS256")]
    [InlineData("")]
    public void Rejects_non_S256_method(string method)
    {
        var result = _sut.Validate(challenge: ValidChallenge, method: method);
        result.IsValid.Should().BeFalse();
        result.Error.Should().Contain("S256");
    }

    [Fact]
    public void Method_match_is_case_sensitive()
    {
        // RFC 7636 §4.3 says the parameter values are case-sensitive.
        var result = _sut.Validate(challenge: ValidChallenge, method: "s256");
        result.IsValid.Should().BeFalse();
    }

    [Theory]
    [InlineData(42)]   // too short — RFC 7636 §4.2 requires >= 43 chars
    [InlineData(43)]   // valid lower bound
    [InlineData(128)]  // valid upper bound
    [InlineData(129)]  // too long
    public void Challenge_length_must_be_43_to_128_chars(int length)
    {
        var challenge = new string('A', length);
        var result = _sut.Validate(challenge: challenge, method: "S256");
        result.IsValid.Should().Be(length is >= 43 and <= 128);
    }

    [Fact]
    public void Challenge_must_be_base64url_charset()
    {
        // 43+ char string with a '+' (not in base64url charset which uses '-' and '_')
        var bad = "A" + new string('B', 41) + "+";  // 43 chars
        var result = _sut.Validate(challenge: bad, method: "S256");
        result.IsValid.Should().BeFalse();
        result.Error.Should().Contain("code_challenge");
    }
}
