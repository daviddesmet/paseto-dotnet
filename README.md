# Paseto.NET, a [Paseto](https://github.com/paragonie/paseto) (Platform-Agnostic Security Tokens) implementation for .NET

[![CI](https://github.com/daviddesmet/paseto-dotnet/actions/workflows/ci.yml/badge.svg)](https://github.com/daviddesmet/paseto-dotnet/actions/workflows/ci.yml)
[![Maintenance](https://img.shields.io/maintenance/yes/2026.svg)](https://github.com/daviddesmet/paseto-dotnet)
[![contributions welcome](https://img.shields.io/badge/contributions-welcome-brightgreen.svg?style=flat)](https://github.com/daviddesmet/paseto-dotnet/issues)

## Table of Contents

- [Features](#features)
- [Installation](#installation)
- [Usage](#usage)
  - [PASETO](#paseto)
  - [PASERK](#paserk)
- [Roadmap](#roadmap)
- [Test Coverage](#test-coverage)
- [Cryptography](#cryptography)
- [Dependency Lock Files](#dependency-lock-files)
- [Learn More](#learn-more)

## Features

PASETO protocols

| purpose | v1 | v2 | v3 | v4 |
| -- | -- | -- | -- | -- |
| local | ✅ | ✅ | ✅ | ✅ |
| public | ✅ | ✅ | ✅ | ✅ |

PASERK extension

| purpose | type | support |
| -- | -- | -- |
| local | local | ✅ |
| local | lid | ✅ |
| local | local-wrap | ✅ |
| local | local-pw | ✅ |
| local | seal | ❌ |
| public | public | ✅ |
| public | pid | ✅ |
| public | secret | ✅ |
| public | sid | ✅ |
| public | secret-wrap | ✅ |
| public | secret-pw | ✅ |

## Installation

[![NuGet Version](https://img.shields.io/nuget/v/Paseto.Core)](https://www.nuget.org/packages/Paseto.Core/)

Targets `net8.0` and `net10.0`.

Install the Paseto.Core NuGet package from the .NET CLI using:
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

> [!NOTE]
> Implicit assertions (`AddImplicitAssertion()`) are only supported by protocol versions **v3** and **v4**. For v1 and v2 tokens the assertion is ignored, as the PASETO spec provides no way to bind it — do not rely on it for those versions.

Below are a couple of examples for the most common use cases:

#### Generating a crypto random Symmetric Key

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
                               .WithKey(key)
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
                                .WithKey(key)
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
                                .WithKey(key)
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
var paserk = Paserk.Encode(pasetoKey, PaserkType.Local);
```

#### Decoding a Key

```csharp
var key = Paserk.Decode(paserk);
```

#### Key identifiers (`lid` / `sid` / `pid`)

Identifier types produce a stable, one-way fingerprint of a key. They can only be encoded — `Paserk.Decode` intentionally throws for them, since an identifier is used to look up a key you already hold, not to recover one.

```csharp
var kid = Paserk.Encode(pasetoKey, PaserkType.Lid); // sid for secret keys, pid for public keys
```

#### Key wrapping (`local-wrap` / `secret-wrap`)

Wraps a key with another symmetric wrapping key using the ["pie" key-wrapping protocol](https://github.com/paseto-standard/paserk/blob/master/operations/Wrap/pie.md) (AES-256-CTR + HMAC-SHA384 for v1/v3, XChaCha20 + BLAKE2b for v2/v4):

```csharp
// wk is a PasetoSymmetricKey used to wrap/unwrap
var paserk = Paserk.Encode(localKey, PaserkType.LocalWrap, wrappingKey);
var key = Paserk.Decode(paserk, wrappingKey);

// or via the builder
var paserk = new PasetoBuilder().Use(ProtocolVersion.V4, Purpose.Local)
                                .WithKey(localKey)
                                .GenerateSerializedKey(PaserkType.LocalWrap, wrappingKey);
```

#### Password-based key wrapping (`local-pw` / `secret-pw`)

Wraps a key with a password using [PBKW](https://github.com/paseto-standard/paserk/blob/master/operations/PBKW.md) (PBKDF2-SHA384 + AES-256-CTR for v1/v3, Argon2id + XChaCha20 for v2/v4). Tune the work factors via `PbkwOptions`:

```csharp
var password = Encoding.UTF8.GetBytes("correct horse battery staple");
var options = new PbkwOptions
{
    MemoryLimitBytes = 67_108_864, // Argon2id (v2/v4)
    OpsLimit = 2,
    Iterations = 100_000,          // PBKDF2 (v1/v3)
};

var paserk = Paserk.Encode(localKey, PaserkType.LocalPassword, password, options);
var key = Paserk.Decode(paserk, password);
```

> [!NOTE]
> The `PbkwOptions` defaults are interactive-grade. For keys stored at rest, raise the work factors (higher `MemoryLimitBytes`/`OpsLimit` for Argon2id, more `Iterations` for PBKDF2) to match your threat model and hardware.

## Roadmap

- [ ] Add support for the `seal` PASERK type (the only remaining [operation](https://github.com/paseto-standard/paserk/blob/master/operations)).
- [ ] Add support for version/purpose detection when decoding a PASETO token (currently required via `Use()`; PASERK already detects the version from the header).
- [ ] Add support for custom payload [validation rules](https://github.com/paseto-standard/paseto-spec/blob/master/docs/02-Implementation-Guide/02-Validators.md).
- [ ] Improve documentation.

## Test Coverage

[![codecov](https://codecov.io/gh/daviddesmet/paseto-dotnet/branch/master/graph/badge.svg?token=O9QHck0xb9)](https://codecov.io/gh/daviddesmet/paseto-dotnet)

- Includes the mandatory [test vectors](https://github.com/paseto-standard/test-vectors) for PASETO and PASERK.

## Cryptography

* **Ed25519** (EdDSA over Curve25519) — bundled managed implementation (originally derived from CodesInChaos [Chaos.NaCl](https://github.com/CodesInChaos/Chaos.NaCl)).
* **BLAKE2b** — bundled managed implementation, plus [Bouncy Castle](https://github.com/novotnyllc/bc-csharp) for key identifiers.
* **AES-256-CTR**, **ECDSA over P-384**, **Argon2id** — [Bouncy Castle](https://github.com/novotnyllc/bc-csharp).
* **XChaCha20** — [NaCl.Core](https://github.com/daviddesmet/NaCl.Core).
* **HMAC-SHA384**, **HKDF-SHA384**, **PBKDF2-SHA384**, **SHA-384** — .NET base class library.

## Dependency Lock Files

The repository uses [NuGet lock files](https://learn.microsoft.com/en-us/nuget/consume-packages/package-references-in-project-files#locking-dependencies) (`packages.lock.json`, committed per project) to pin the full dependency graph, including transitive packages. CI restores with locked mode enabled, so a build fails if the resolved packages differ from the lock files — protecting against floating transitive versions and dependency-confusion attacks.

Upgrading packages therefore changes slightly:

- Edit the package version in the `.csproj` (or let Dependabot do it), then run `dotnet restore --force-evaluate` from the repository root and commit the updated `packages.lock.json` files together with the `.csproj` change.
- Dependabot PRs update the lock files automatically.
- A plain `dotnet restore` locally never floats versions; it follows the lock files. If it reports `NU1004`, the lock files are out of date — run `dotnet restore --force-evaluate`.

## Learn More

[![License](https://img.shields.io/github/license/daviddesmet/paseto-dotnet.svg)](https://github.com/daviddesmet/paseto-dotnet/blob/master/LICENSE)

* [PASETO (Platform-Agnostic SEcurity TOkens)](https://github.com/paseto-standard/paseto-spec) is a specification and reference implementation for secure stateless tokens.
* [PASERK (Platform-Agnostic SERialized Keys)](https://github.com/paseto-standard/paserk) is an extension to PASETO that provides key-wrapping and serialization.
