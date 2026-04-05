namespace EntraMcpProxy.Configuration;

public class DownstreamServerConfig
{
    public string Name { get; set; } = "";
    public string Prefix { get; set; } = "";
    public string BaseUrl { get; set; } = "";
    public string AuthType { get; set; } = "ApiKey";
    public string? ApiKey { get; set; }
    public EntraIdConfig? EntraId { get; set; }
    public OBOConfig? OBO { get; set; }
    public bool Enabled { get; set; } = true;
    public int TimeoutSeconds { get; set; } = 30;
}

public class EntraIdConfig
{
    public string TenantId { get; set; } = "";
    public string ClientId { get; set; } = "";
    public string ClientSecret { get; set; } = "";
    public string Scope { get; set; } = "";
}

public class OBOConfig
{
    public string TenantId { get; set; } = "";
    public string ClientId { get; set; } = "";
    public string ClientSecret { get; set; } = "";
    public string TargetScope { get; set; } = "";
}
