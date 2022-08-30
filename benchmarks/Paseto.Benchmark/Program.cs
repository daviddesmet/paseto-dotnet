using System;
using BenchmarkDotNet.Attributes;
using BenchmarkDotNet.Jobs;
using BenchmarkDotNet.Running;
using Paseto;
using Paseto.Builder;
using Paseto.Cryptography.Key;
using Xunit;

BenchmarkRunner.Run<Benchmarks>();

[MemoryDiagnoser]
[SimpleJob(RuntimeMoniker.Net50)]
[SimpleJob(RuntimeMoniker.Net60)]
[JsonExporterAttribute.Full]
[JsonExporterAttribute.FullCompressed]
public class Benchmarks
{
    private readonly byte[] _seed = new byte[32];
    private PasetoSymmetricKey _symmetricKey = null!;
    private PasetoAsymmetricKeyPair _asymmetricKeyPair = null!;
    private string _localToken = null!;
    private string _publicToken = null!;

    [GlobalSetup]
    public void SetUp()
    {
        _symmetricKey = new PasetoBuilder().Use(Version, Purpose.Local).GenerateSymmetricKey();
        _asymmetricKeyPair = new PasetoBuilder().Use(Version, Purpose.Public).GenerateAsymmetricKeyPair(_seed);

        _localToken = Encrypt();
        _publicToken = Sign();
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
    public string Encrypt() => CreateBuilder().Use(Version, Purpose.Local)
                              .WithKey(_symmetricKey)
                              .Encode();

    [Benchmark]
    public PasetoTokenValidationResult Decrypt()
    {
        var result = CreateBuilder().Use(Version, Purpose.Local)
                                    .WithKey(_symmetricKey)
                                    .Decode(_localToken);

        Assert.True(result.IsValid);
        return result;
    }

    [Benchmark]
    public string Sign() => CreateBuilder().Use(Version, Purpose.Public)
                                                   .WithKey(_asymmetricKeyPair.SecretKey)
                                                   .Encode();

    [Benchmark]
    public PasetoTokenValidationResult Verify()
    {
        var result = CreateBuilder().Use(Version, Purpose.Public)
                                    .WithKey(_asymmetricKeyPair.PublicKey)
                                    .Decode(_publicToken);

        Assert.True(result.IsValid);
        return result;
    }
}