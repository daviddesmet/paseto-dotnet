# Paseto.NET, a [Paseto](https://github.com/paragonie/paseto) (Platform-Agnostic Security Tokens) implementation for .NET

[![Build status](https://ci.appveyor.com/api/projects/status/r4ah81nr04qta10w?svg=true)](https://ci.appveyor.com/project/idaviddesmet/paseto-dotnet)
[![Build Status](https://travis-ci.org/idaviddesmet/paseto-dotnet.svg?branch=master)](https://travis-ci.org/idaviddesmet/paseto-dotnet)
[![NuGet](https://img.shields.io/nuget/v/Paseto.Core.svg)](https://www.nuget.org/packages/Paseto.Core/)
[![MyGet](https://img.shields.io/myget/paseto/v/Paseto.Core.svg)](https://www.myget.org/feed/paseto/package/nuget/Paseto.Core)
[![Maintenance](https://img.shields.io/maintenance/yes/2018.svg)](https://github.com/idaviddesmet/paseto-dotnet)
[![License](https://img.shields.io/github/license/idaviddesmet/paseto-dotnet.svg)](https://github.com/idaviddesmet/paseto-dotnet/blob/master/LICENSE)
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
var encoder = new PasetoEncoder(cfg => cfg.Use<Version2>(secret)); // default is public purpose
var token = encoder.Encode(new PasetoPayload
{
	{ "example", "Hello Paseto!" },
	{ "exp", UnixEpoch.ToUnixTime(DateTime.UtcNow.AddHours(24)) }
});
```

#### Encoded Token:

```
v2.public.eyJleGFtcGxlIjoiSGVsbG8gUGFzZXRvISIsImV4cCI6IjE1MjEyNDU0NTAifQ2jznA4Tl8r2PM8xu0FIJhyWkm4SiwvCxavTSFt7bo7JtnsFdWgXBOgbYybi5-NAkmpm94uwJCRjCApOXBSIgs
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
var decoder = new PasetoDecoder(cfg => cfg.Use<Version2>(publicKey)); // default is public purpose
var payload = decoder.Decode(token);
```

#### Decrypted Payload:

```json
{
  "example": "Hello Paseto!",
  "exp": "1521245450"
}
```

## Roadmap

- [x] Add support for local authentication for v2
  - [x] Implement XChaCha20-Poly1305 algorithm ~~or use an external library~~
- [ ] Add support for local authentication for v1
- [ ] Improve protocol versioning
- [ ] Add more documentation on the usage
- [ ] Extend the fluent builder API
- [ ] Add more tests

## Cryptography

* Uses Ed25519 algorithm from CodesInChaos [Chaos.NaCl](https://github.com/CodesInChaos/Chaos.NaCl) cryptography library.

At its current state, [libsodium-core](https://github.com/tabrath/libsodium-core) and [NSec](https://github.com/ektrah/nsec) does't support XChaCha20-Poly1305.
