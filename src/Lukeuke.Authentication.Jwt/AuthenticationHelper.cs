using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using Microsoft.IdentityModel.Tokens;

namespace Lukeuke.Authentication.Jwt;

/// <summary>
/// Provides helper methods for generating JWT tokens, hashing passwords, and managing claims.
/// </summary>
public static class AuthenticationHelper
{
    private static readonly RandomNumberGenerator Rng = RandomNumberGenerator.Create();
    
    /// <summary>
    /// Generates a random salt.
    /// </summary>
    /// <param name="size">The size of the salt in bytes.</param>
    /// <returns>A byte array containing the generated salt.</returns>
    private static byte[] GenerateSalt(uint size)
    {
        var salt = new byte[size];
        Rng.GetBytes(salt);
        return salt;
    }

    /// <summary>
    /// Generates a secure hash for a given password and salt.
    /// </summary>
    /// <param name="password">The password to hash.</param>
    /// <param name="salt">The salt to use for hashing (base64-encoded).</param>
    /// <returns>A base64-encoded hash string.</returns>
    /// <exception cref="FormatException">Thrown if the salt is not a valid base64 string.</exception>
    public static string GenerateHash(string password, string salt)
    {
        var saltBytes = Convert.FromBase64String(salt);

        using var hashGenerator = new Rfc2898DeriveBytes(password, saltBytes)
        {
            IterationCount = 10101
        };
        
        var bytes = hashGenerator.GetBytes(24);
        return Convert.ToBase64String(bytes);
    }

    /// <summary>
    /// Provides a salt and generates a hash for the user's password, modifying the user object in place.
    /// </summary>
    /// <param name="user">The identity user object to modify.</param>
    /// <param name="saltSize">The size of the salt to generate (default is 24 bytes).</param>
    public static void ProvideSaltAndHash(this IdentityUser user, uint saltSize = 24)
    {
        var salt = GenerateSalt(saltSize);
        user.Salt = Convert.ToBase64String(salt);
        user.PasswordHash = GenerateHash(user.PasswordHash, user.Salt);
    }
    
    /// <summary>
    /// Generates a JWT token.
    /// </summary>
    /// <param name="settings">The JWT settings containing secret key, issuer, and expiration details.</param>
    /// <param name="subject">The claims identity to include in the token.</param>
    /// <param name="securityAlgorithm">The security algorithm to use (default is HMAC SHA256).</param>
    /// <returns>The generated JWT token as a string.</returns>
    public static string GenerateJwt(JwtSettings settings, ClaimsIdentity subject, string securityAlgorithm = SecurityAlgorithms.HmacSha256Signature)
    {
        var tokenHandler = new JwtSecurityTokenHandler();
        var key = Encoding.ASCII.GetBytes(settings.BearerKey);
        var tokenDescriptor = new SecurityTokenDescriptor
        {
            Subject = subject,
            Expires = DateTime.Now.AddSeconds(settings.ExpiresInSeconds),
            SigningCredentials =
                new SigningCredentials(new SymmetricSecurityKey(key), securityAlgorithm)
        };

        if (!string.IsNullOrEmpty(settings.Issuer))
        {
            tokenDescriptor.Issuer = settings.Issuer;
            tokenDescriptor.IssuedAt = DateTime.Now;
        }
        
        var token = tokenHandler.CreateToken(tokenDescriptor);
        return tokenHandler.WriteToken(token);
    }

    /// <summary>
    /// Assembles a ClaimsIdentity from a collection of claims.
    /// </summary>
    /// <param name="claims">The collection of claims.</param>
    /// <returns>A ClaimsIdentity object containing the specified claims.</returns>
    public static ClaimsIdentity AssembleClaimsIdentity(IEnumerable<Claim> claims)
    {
        var subject = new ClaimsIdentity(claims);
        return subject;
    }
}