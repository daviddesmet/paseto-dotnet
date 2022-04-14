# Paseto.NET, a [Paseto](https://github.com/paragonie/paseto) (Platform-Agnostic Security Tokens) implementation for .NET

[![Build status](https://ci.appveyor.com/api/projects/status/r4ah81nr04qta10w?svg=true)](https://ci.appveyor.com/project/idaviddesmet/paseto-dotnet)
[![Build Status](https://travis-ci.org/idaviddesmet/paseto-dotnet.svg?branch=master)](https://travis-ci.org/idaviddesmet/paseto-dotnet)
[![NuGet](https://img.shields.io/nuget/v/Paseto.Core.svg)](https://www.nuget.org/packages/Paseto.Core/)
[![MyGet](https://img.shields.io/myget/paseto/v/Paseto.Core.svg)](https://www.myget.org/feed/paseto/package/nuget/Paseto.Core)
[![Maintenance](https://img.shields.io/maintenance/yes/2022.svg)](https://github.com/daviddesmet/paseto-dotnet)
[![License](https://img.shields.io/github/license/idaviddesmet/paseto-dotnet.svg)](https://github.com/daviddesmet/paseto-dotnet/blob/master/LICENSE)
[![contributions welcome](https://img.shields.io/badge/contributions-welcome-brightgreen.svg?style=flat)](https://github.com/daviddesmet/paseto-dotnet/issues)

## Features

PASETO protocols

| purpose | v1 | v2 | v3 | v4 |
| -- | -- | -- | -- | -- |
| local | ✅ | ✅ | ✅ | ✅ |
| public | ✅ | ✅ | ✅ | ✅ |

PASERK extension

| type | support |
| -- | -- |
| lid | ❌ |
| local | ✅ |
| seal | ❌ |
| local-wrap | ❌ |
| local-pw | ❌ |
| sid | ❌ |
| public | ✅ |
| pid | ❌ |
| secret | ✅ |
| secret-wrap | ❌ |
| secret-pw | ❌ |

## Usage for PASETO

The library exposes a Fluent API with several method overloads found in `Use()`, `WithKey()`, `AddClaim()`, `AddFooter()` and so on to provide the flexibility needed for encoding and decoding PASETO tokens and also for generating the required symmetric or asymmetric key pairs. However, you can use the Protocols and Handlers directly if you like.

Below are a couple of examples for the most common use cases:

### Generating a Symmetric Key

```csharp
var pasetoKey = new PasetoBuilder().Use(version, Purpose.Local)
                                   .GenerateSymmetricKey();
```

### Generating an Asymmetric Key Pair

```csharp
var pasetoKey = new PasetoBuilder().Use(version, Purpose.Public)
                                   .GenerateAsymmetricKeyPair(seed);
```

**NOTE:** A seed is not required for protocol v1.

### Generating a Token

```csharp
var token = new PasetoBuilder().Use(version, purpose)
                               .WithKey(key, encryption)
                               .AddClaim("data", "this is a secret message")
                               .Issuer("https://github.com/daviddesmet/paseto-dotnet")
                               .Subject(Guid.NewGuid().ToString())
                               .Audience("https://paseto.io")
                               .NotBefore(DateTime.UtcNow.AddMinutes(5))
                               .IssuedAt(DateTime.UtcNow)
                               .Expiration(DateTime.UtcNow.AddHours(1))
                               .TokenIdentifier("123456ABCD")
                               .AddFooter("arbitrary-string-that-isn't-json")
                               .Encode();
```

### Decoding a Token

```csharp
var result = new PasetoBuilder().Use(version, purpose)
                                .WithKey(key, encryption)
                                .Decode(token);
```

## Usage for PASERK

The library also provides the PASERK extension for encoding and decoding a key.

A serialized key in PASERK has the format:

```
k[version].[type].[data]
```

### Encoding a Key

```csharp
var paserk = Paserk.Encode(pasetoKey, purpose, type);
```

### Decoding a Key

```csharp
var key = Paserk.Decode(paserk);
```

## Roadmap

- [ ] Add support for remaining PASERK types and its [operations](https://github.com/paseto-standard/paserk/blob/master/operations).
- [ ] Add support for version detection when decoding.
- [ ] Add payload [validation rules](https://github.com/paseto-standard/paseto-spec/blob/master/docs/02-Implementation-Guide/02-Validators.md).
  - There's already an [initial implementation](https://github.com/daviddesmet/paseto-dotnet/commit/0f25cb5f7d937ebf2396d15572c16ac16690f68b) and [tests](https://github.com/idaviddesmet/paseto-dotnet/blob/9adb1a575afdc8722e1772109d0885413ff22cf8/src/Paseto.Tests/PasetoTests.cs#L554).
- [ ] Add more documentation on the usage.

## Test Coverage

- Includes the mandatory [test vectors](https://github.com/paseto-standard/test-vectors) for PASETO and PASERK.

## Cryptography

* Uses Ed25519 algorithm from CodesInChaos [Chaos.NaCl](https://github.com/CodesInChaos/Chaos.NaCl) cryptography library.
* Uses Blake2b cryptographic hash function from [Konscious.Security.Cryptography](https://github.com/kmaragon/Konscious.Security.Cryptography) repository.
* Uses ECDSA algorithm from [Bouncy Castle](https://github.com/novotnyllc/bc-csharp) cryptography library.
* Uses XChaCha20-Poly1305 AEAD from [NaCl.Core](https://github.com/daviddesmet/NaCl.Core) repository.

## Learn More

* [PASETO (Platform-Agnostic SEcurity TOkens)](https://github.com/paseto-standard/paseto-spec) is a specification and reference implementation for secure stateless tokens.
* [PASERK (Platform-Agnostic SERialized Keys)](https://github.com/paseto-standard/paserk) is an extension to PASETO that provides key-wrapping and serialization.