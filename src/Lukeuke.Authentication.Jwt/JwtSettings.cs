namespace Lukeuke.Authentication.Jwt;

/// <summary>
/// Configuration settings for generating JWT tokens.
/// </summary>
public class JwtSettings
{
    /// <summary>
    /// The secret key used for signing the token (must be a secure, random string).
    /// </summary>
    public string BearerKey { get; set; } = string.Empty;

    /// <summary>
    /// The issuer of the token.
    /// </summary>
    public string? Issuer { get; set; }

    /// <summary>
    /// The token expiration time in seconds.
    /// </summary>
    public int ExpiresInSeconds { get; set; }
}