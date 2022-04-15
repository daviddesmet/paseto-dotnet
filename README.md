# Paseto.NET, a [Paseto](https://github.com/paragonie/paseto) (Platform-Agnostic Security Tokens) implementation for .NET

[![CI](https://github.com/daviddesmet/paseto-dotnet/workflows/CI/badge.svg?branch=master)](https://github.com/daviddesmet/paseto-dotnet/actions)
[![Build Status](https://travis-ci.org/idaviddesmet/paseto-dotnet.svg?branch=master)](https://travis-ci.org/idaviddesmet/paseto-dotnet)
[![Maintenance](https://img.shields.io/maintenance/yes/2022.svg)](https://github.com/daviddesmet/paseto-dotnet)
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

## Installation

[![NuGet](https://buildstats.info/nuget/Paseto.Core)](https://www.nuget.org/packages/Paseto.Core/)
[![MyGet](https://img.shields.io/myget/paseto/v/Paseto.Core.svg)](https://www.myget.org/feed/paseto/package/nuget/Paseto.Core)

Install the Paseto.Core NuGet package from the .NET Core CLI using:
```
dotnet add package Paseto.Core
```

or from the NuGet package manager:
```
Install-Package Paseto.Core
```

## Usage

[![](https://img.shields.io/nuget/dt/Paseto.Core.svg)](https://www.nuget.org/packages/Paseto.Core/)

### PASETO

The library exposes a Fluent API with several method overloads found in `Use()`, `WithKey()`, `AddClaim()`, `AddFooter()` and so on to provide the flexibility needed for encoding and decoding PASETO tokens and also for generating the required symmetric or asymmetric key pairs. However, you can use the Protocols and Handlers directly if you like.

Below are a couple of examples for the most common use cases:

#### Generating a Symmetric Key

```csharp
var pasetoKey = new PasetoBuilder().Use(version, Purpose.Local)
                                   .GenerateSymmetricKey();
```

#### Generating an Asymmetric Key Pair

```csharp
var pasetoKey = new PasetoBuilder().Use(version, Purpose.Public)
                                   .GenerateAsymmetricKeyPair(seed);
```

**NOTE:** A seed is not required for protocol v1.

#### Generating a Token

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

#### Decoding a Token

```csharp
var result = new PasetoBuilder().Use(version, purpose)
                                .WithKey(key, encryption)
                                .Decode(token);
```

Or validate the token's payload while decoding (the header and signature is always validated):

```csharp
var valParams = new PasetoTokenValidationParameters
{
    ValidateLifetime = true,
    ValidateAudience = true,
    ValidateIssuer = true,
    ValidAudience = "https://paseto.io",
    ValidIssuer = "https://github.com/daviddesmet/paseto-dotnet"
};

var result = new PasetoBuilder().Use(version, purpose)
                                .WithKey(key, encryption)
                                .Decode(token, valParams);
```

### PASERK

The library also provides the PASERK extension for encoding and decoding a key.

A serialized key in PASERK has the format:

```
k[version].[type].[data]
```

#### Encoding a Key

```csharp
var paserk = Paserk.Encode(pasetoKey, purpose, type);
```

#### Decoding a Key

```csharp
var key = Paserk.Decode(paserk);
```

## Roadmap

- [ ] Add support for remaining PASERK types and its [operations](https://github.com/paseto-standard/paserk/blob/master/operations).
- [ ] Add support for version detection when decoding.
- [ ] Add support for custom payload [validation rules](https://github.com/paseto-standard/paseto-spec/blob/master/docs/02-Implementation-Guide/02-Validators.md).
- [ ] Add Fluent-API payload validation unit tests.
- [ ] Remove dependency on JSON.NET.

## Test Coverage

- Includes the mandatory [test vectors](https://github.com/paseto-standard/test-vectors) for PASETO and PASERK.

## Cryptography

* Uses Ed25519 (EdDSA over Curve25519) algorithm from CodesInChaos [Chaos.NaCl](https://github.com/CodesInChaos/Chaos.NaCl) cryptography library.
* Uses Blake2b cryptographic hash function from [Konscious.Security.Cryptography](https://github.com/kmaragon/Konscious.Security.Cryptography) repository.
* Uses AES-256-CTR, ECDSA over P-384 algorithms from [Bouncy Castle](https://github.com/novotnyllc/bc-csharp) cryptography library.
* Uses XChaCha20-Poly1305 AEAD from [NaCl.Core](https://github.com/daviddesmet/NaCl.Core) repository.

## Learn More

[![License](https://img.shields.io/github/license/daviddesmet/paseto-dotnet.svg)](https://github.com/daviddesmet/paseto-dotnet/blob/master/LICENSE)

* [PASETO (Platform-Agnostic SEcurity TOkens)](https://github.com/paseto-standard/paseto-spec) is a specification and reference implementation for secure stateless tokens.
* [PASERK (Platform-Agnostic SERialized Keys)](https://github.com/paseto-standard/paserk) is an extension to PASETO that provides key-wrapping and serialization.
