# Paseto.NET, a [Paseto](https://github.com/paragonie/paseto) (Platform-Agnostic Security Tokens) implementation for .NET

## Usage
### Building a Paseto

```csharp
var token = new PasetoBuilder<Version2>()
		.WithKey(sharedKey)
		.WithExpiration(DateTime.UtcNow.AddMinutes(120))
		.AddClaim("data", "this is a signed message")
		.AddClaim("example", "Hello world")
		.AsPublic() // Purpose
		.Build();
```

## Credits
* CodesInChaos for the [Chaos.NaCl](https://github.com/CodesInChaos/Chaos.NaCl) cryptography library.
