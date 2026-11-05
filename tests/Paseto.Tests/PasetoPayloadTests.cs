namespace Paseto.Tests;

using System;
using System.Collections.Generic;
using System.Text.Json;
using System.Text.Json.Serialization;

using Shouldly;
using Xunit;

using Paseto.Builder;

[Trait("Category", "CI")]
public class PasetoPayloadTests
{
    private static readonly DateTime Expiration = new(2030, 1, 2, 3, 4, 5, DateTimeKind.Utc);

    private sealed class Address
    {
        public string City { get; set; }
        public int Zip { get; set; }
    }

    private sealed class CollidingNames
    {
        [JsonPropertyName("a")]
        public string First { get; set; }

        [JsonPropertyName("a")]
        public string Second { get; set; }
    }

    private sealed class Claims
    {
        [JsonPropertyName("sub")]
        public string Subject { get; set; }

        [JsonPropertyName("exp")]
        public DateTime Expiration { get; set; }

        [JsonPropertyName("roles")]
        public string[] Roles { get; set; }
    }

    private static PasetoToken DecodeSampleToken()
    {
        var key = new PasetoBuilder().Use(ProtocolVersion.V4, Purpose.Local).GenerateSymmetricKey();

        var token = new PasetoBuilder().Use(ProtocolVersion.V4, Purpose.Local)
                                       .WithKey(key)
                                       .Subject("alice")
                                       .Expiration(Expiration)
                                       .AddClaim("count", 42)
                                       .AddClaim("big", 9_000_000_000L)
                                       .AddClaim("admin", true)
                                       .AddClaim("roles", new[] { "read", "write" })
                                       .AddClaim("address", new Address { City = "Ghent", Zip = 9000 })
                                       .Encode();

        var result = new PasetoBuilder().Use(ProtocolVersion.V4, Purpose.Local).WithKey(key).Decode(token);
        result.IsValid.ShouldBeTrue();
        return result.Paseto;
    }

    [Fact]
    public void DecodedClaimValuesAreJsonElements()
    {
        var payload = DecodeSampleToken().Payload;

        payload["count"].ShouldBeOfType<JsonElement>();
        payload["sub"].ShouldBeOfType<JsonElement>();
    }

    [Fact]
    public void GetClaimConvertsDecodedValues()
    {
        var payload = DecodeSampleToken().Payload;

        payload.GetClaim<string>("sub").ShouldBe("alice");
        payload.GetClaim<int>("count").ShouldBe(42);
        payload.GetClaim<long>("big").ShouldBe(9_000_000_000L);
        payload.GetClaim<bool>("admin").ShouldBeTrue();
        payload.GetClaim<DateTime>("exp").ToUniversalTime().ShouldBe(Expiration);
        payload.GetClaim<string[]>("roles").ShouldBe(new[] { "read", "write" });
        payload.GetClaim<List<string>>("roles").ShouldBe(new List<string> { "read", "write" });

        var address = payload.GetClaim<Address>("address");
        address.City.ShouldBe("Ghent");
        address.Zip.ShouldBe(9000);
    }

    [Fact]
    public void GetClaimHandlesValuesThatWereNotEncoded()
    {
        var payload = new PasetoPayload { ["count"] = 42, ["name"] = "bob" };

        payload.GetClaim<int>("count").ShouldBe(42);
        payload.GetClaim<long>("count").ShouldBe(42L);
        payload.GetClaim<string>("name").ShouldBe("bob");
    }

    [Fact]
    public void GetClaimThrowsWhenClaimIsMissing()
    {
        var payload = DecodeSampleToken().Payload;

        Should.Throw<KeyNotFoundException>(() => payload.GetClaim<string>("missing"));
    }

    [Fact]
    public void TryGetClaimReportsMissingAndUnconvertibleClaims()
    {
        var payload = DecodeSampleToken().Payload;

        payload.TryGetClaim<int>("count", out var count).ShouldBeTrue();
        count.ShouldBe(42);

        payload.TryGetClaim<int>("missing", out var missing).ShouldBeFalse();
        missing.ShouldBe(0);

        payload.TryGetClaim<int>("sub", out var wrongType).ShouldBeFalse();
        wrongType.ShouldBe(0);
    }

    [Fact]
    public void GetPayloadDeserializesIntoCustomType()
    {
        var claims = DecodeSampleToken().GetPayload<Claims>();

        claims.Subject.ShouldBe("alice");
        claims.Expiration.ToUniversalTime().ShouldBe(Expiration);
        claims.Roles.ShouldBe(new[] { "read", "write" });
    }

    [Fact]
    public void GetClaimHonoursSerializerOptions()
    {
        using var doc = JsonDocument.Parse("{\"city\":\"Ghent\",\"zip\":9000}");
        var payload = new PasetoPayload { ["address"] = doc.RootElement.Clone() };

        // Matching is case-sensitive by default; options make it case-insensitive.
        payload.GetClaim<Address>("address").City.ShouldBeNull();

        var options = new JsonSerializerOptions { PropertyNameCaseInsensitive = true };
        var address = payload.GetClaim<Address>("address", options);
        address.City.ShouldBe("Ghent");
        address.Zip.ShouldBe(9000);
    }

    [Fact]
    public void NullClaimValueConvertsToDefault()
    {
        var payload = new PasetoPayload { ["nothing"] = null };

        payload.GetClaim<string>("nothing").ShouldBeNull();
        payload.TryGetClaim<int?>("nothing", out var value).ShouldBeTrue();
        value.ShouldBeNull();
    }

    [Fact]
    public void TryGetClaimReturnsFalseForUnsupportedTargetType()
    {
        // System.Text.Json refuses to deserialize System.Type (NotSupportedException).
        var payload = DecodeSampleToken().Payload;

        payload.TryGetClaim<Type>("sub", out var value).ShouldBeFalse();
        value.ShouldBeNull();
    }

    [Fact]
    public void TryGetClaimReturnsFalseForInvalidTargetType()
    {
        // Two properties mapped to the same JSON name make System.Text.Json throw InvalidOperationException.
        var payload = DecodeSampleToken().Payload;

        payload.TryGetClaim<CollidingNames>("address", out var value).ShouldBeFalse();
        value.ShouldBeNull();
    }
}
