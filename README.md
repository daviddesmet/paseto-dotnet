# Paseto.NET, a [Paseto](https://github.com/paragonie/paseto) (Platform-Agnostic Security Tokens) implementation for .NET

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

### Decoding a Paseto

```csharp
var token = new PasetoBuilder<Version2>()
		.WithKey(publicKey)
		.AsPublic() // Purpose
		.AndVerifySignature()
		.Decode(token);
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