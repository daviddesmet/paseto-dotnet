using System;
using BenchmarkDotNet.Attributes;
using BenchmarkDotNet.Jobs;
using BenchmarkDotNet.Running;
using Paseto;
using Paseto.Builder;
using Paseto.Cryptography.Key;
using Paseto.Tests;
using Xunit;

BenchmarkRunner.Run<Benchmarks>();

[MemoryDiagnoser]
[SimpleJob(RuntimeMoniker.Net60)]
[SimpleJob(RuntimeMoniker.Net80)]
[JsonExporterAttribute.Full]
[JsonExporterAttribute.FullCompressed]
public class Benchmarks
{
    private readonly byte[] _seed = new byte[32];
    private readonly byte[] _symmetricKey = TestHelper.FromHexString("707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f");
    private PasetoAsymmetricKeyPair _asymmetricKeyPair = null!;

    private string _expectedLocalToken = null!;
    private string _expectedPublicToken = null!;
    private PasetoBuilder _builder = null!;

    [GlobalSetup]
    public void SetUp()
    {
        _asymmetricKeyPair = new PasetoBuilder().Use(Version, Purpose.Public).GenerateAsymmetricKeyPair(_seed);
        _builder = CreateBuilder();

        _expectedLocalToken = Encrypt();
        _expectedPublicToken = Sign();

    }

    [ParamsAllValues]
    public ProtocolVersion Version { get; set; }

    // TODO Experiment with a large claim/many claims
    public static PasetoBuilder CreateBuilder() => new PasetoBuilder().Issuer("localhost:5000")
                                                                      .Subject("PASETO-DEMO")
                                                                      .Audience("paseto.io")
                                                                      .NotBefore(DateTime.UtcNow)
                                                                      .IssuedAt(DateTime.UtcNow)
                                                                      .Expiration(DateTime.UtcNow.AddHours(1))
                                                                      .AddClaim("Test", "Value")
                                                                      .AddClaim("Test2", "Value2");

    [Benchmark]
    public string Encrypt() => _builder.Use(Version, Purpose.Local)
                              .WithKey(_symmetricKey, Encryption.SymmetricKey)
                              .Encode();

    [Benchmark]
    public PasetoTokenValidationResult Decrypt()
    {
        var result = _builder.Use(Version, Purpose.Local)
                             .WithKey(_symmetricKey, Encryption.SymmetricKey)
                             .Decode(_expectedLocalToken);

        Assert.True(result.IsValid);
        return result;
    }

    [Benchmark]
    public string Sign() => _builder.Use(Version, Purpose.Public)
                                    .WithKey(_asymmetricKeyPair.SecretKey)
                                    .Encode();

    [Benchmark]
    public PasetoTokenValidationResult Verify()
    {
        var result = _builder.Use(Version, Purpose.Public)
                             .WithKey(_asymmetricKeyPair.PublicKey)
                             .Decode(_expectedPublicToken);

        Assert.True(result.IsValid);
        return result;
    }
}