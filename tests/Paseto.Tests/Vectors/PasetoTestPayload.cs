﻿namespace Paseto.Tests.Vectors;

using System;
using Newtonsoft.Json;

public class PasetoTestPayload
{
    public string Data { get; set; }

    public DateTime Exp { get; set; }

    [JsonProperty("exp")]
    public string ExpString { get; set; }
}
