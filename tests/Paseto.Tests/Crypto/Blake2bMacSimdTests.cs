﻿namespace Paseto.Tests.Crypto;

using System;
using Shouldly;
using Xunit;
using Xunit.Abstractions;
using Paseto.Cryptography;

/// <summary>
/// Tests that assert that the non-HW-accelerated version works
/// </summary>
public class Blake2bMacSimdTests
{
    private readonly ITestOutputHelper _output;

    public Blake2bMacSimdTests(ITestOutputHelper helper) => _output = helper;

    [Fact]
    public void CorrectlyComputesShortHash512() => AssertMatch(_output, 0x5069230, 9, 512, 512);

    [Fact]
    public void CorrectlyComputesShortHash128() => AssertMatch(_output, 0x102193, 3, 128, 128);

    [Fact]
    public void CorrectlyComputesHash256With512BitKey() => AssertMatch(_output, 0x80f39c2, 157, 256, 512);

    [Fact]
    public void CorrectlyComputesHash256With128BitKey() => AssertMatch(_output, 0x12c7361f, 195, 256, 128);

    [Fact]
    public void CorrectlyComputesExactBoundaryHash512() => AssertMatch(_output, 0x5fc00893, 64, 512, 512);

    [Fact]
    public void CorrectlyComputesLongNonBoundary512() => AssertMatch(_output, 0x750a6700, 176, 512, 512);

    [Fact]
    public void CorrectlyComputesLongBoundaryAligned512() => AssertMatch(_output, 0x240f5a03, 640, 512, 512);

    [Fact]
    public void CorrectlyComputesLongBoundary512WithNonBoundaryKey() => AssertMatch(_output, 0x3f078897, 640, 512, 232);

    [Fact]
    public void CorrectlyComputesLongNonBoundary512WithNonBoundaryKey() => AssertMatch(_output, 0xa089e023, 521, 512, 368);

    [Fact]
    public void CorrectlyComputesLargeAligned128() => AssertMatch(_output, 0x1947850, 1024 * 1024 * 10, 128, 128);

    private static void AssertMatch(ITestOutputHelper output, uint seed, int dataSize, int hashSize, int keySize)
    {
        var rand = new Random((int)seed);
        var data = new byte[dataSize];
        var key = new byte[keySize / 8];

        rand.NextBytes(data);
        rand.NextBytes(key);

        var start = DateTime.Now;
        var slow = new Blake2bMac(key, hashSize, () => new Blake2bSlow(hashSize / 8));
        slow.Initialize();
        var slowHash = slow.ComputeHash(data);
        var slowTime = (DateTime.Now - start).TotalMilliseconds * 1000;

        start = DateTime.Now;
        var normal = new Blake2bMac(key, hashSize, () => new Blake2bSimd(hashSize / 8));
        normal.Initialize();
        var normalHash = normal.ComputeHash(data);
        var normalTime = (DateTime.Now - start).TotalMilliseconds * 1000;

        start = DateTime.Now;
        //var b2core = Blake2Core.Blake2B.Create(new Blake2BConfig()
        //{
        //    Key = key,
        //    OutputSizeInBits = hashSize
        //});
        //b2core.Init();
        //b2core.Update(data);
        //var b2CoreHash = b2core.Finish();
        //var b2CoreTime = (DateTime.Now - start).TotalMilliseconds * 1000;

        //output.WriteLine($"Slow path took {slowTime} micros, Normal path took {normalTime} micros, 3rd Party path took {b2CoreTime} micros");
        output.WriteLine($"Slow path took {slowTime} micros, Normal path took {normalTime} micros");
        slowHash.ShouldBeEquivalentTo(normalHash);
        //Assert.Equal(b2CoreHash, normalHash);
    }
}
