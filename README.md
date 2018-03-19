# Paseto.NET, a [Paseto](https://github.com/paragonie/paseto) (Platform-Agnostic Security Tokens) implementation for .NET

[![Build status](https://ci.appveyor.com/api/projects/status/r4ah81nr04qta10w?svg=true)](https://ci.appveyor.com/project/idaviddesmet/paseto-dotnet)
[![NuGet](https://img.shields.io/nuget/v/Paseto.Core.svg)](https://www.nuget.org/packages/Paseto.Core/)
[![MyGet](https://img.shields.io/myget/paseto/v/Paseto.Core.svg)](https://www.myget.org/feed/paseto/package/nuget/Paseto.Core)
[![contributions welcome](https://img.shields.io/badge/contributions-welcome-brightgreen.svg?style=flat)](https://github.com/idaviddesmet/paseto-dotnet/issues)

## Usage
### Building a Paseto

```csharp
var token = new PasetoBuilder<Version2>()
		.WithKey(secret)
		.AddClaim("example", "Hello Paseto!")
		.Expiration(DateTime.UtcNow.AddHours(24))
		.AsPublic() // Purpose
		.Build();
```

```csharp
var encoder = new PasetoEncoder(cfg => cfg.Use<Version2>(sk)); // defaul is public purpose
var token = encoder.Encode(new PasetoPayload
{
	{ "example", HelloPaseto },
	{ "exp", UnixEpoch.GetSecondsSinceAsString(DateTime.UtcNow.AddHours(24)) }
});
```

### Decoding a Paseto

```csharp
var payload = new PasetoBuilder<Version2>()
		.WithKey(publicKey)
		.AsPublic() // Purpose
		.AndVerifySignature()
		.Decode(token);
```

```csharp
var decoder = new PasetoDecoder(cfg => cfg.Use<Version2>(publicKey)); // defaul is public purpose
var payload = decoder.Decode(token);
```

## Roadmap

- [ ] Add support for local authentication for v1 and v2.
  - [ ] Implement XChaCha20-Poly1305 algorithm or use an external library
- [ ] Improve protocol versioning
- [ ] Add more documentation on the usage
- [ ] Extend the fluent builder API
- [ ] Add more tests

## Cryptography

* Uses Ed25519 algorithm from CodesInChaos [Chaos.NaCl](https://github.com/CodesInChaos/Chaos.NaCl) cryptography library.

At its current state, [libsodium-core](https://github.com/tabrath/libsodium-core) and [NSec](https://github.com/ektrah/nsec) does't support XChaCha20-Poly1305.
