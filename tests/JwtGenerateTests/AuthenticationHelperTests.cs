using System.Security.Claims;
using Lukeuke.Authentication.Jwt;

namespace JwtGenerateTests;

[TestFixture]
public class AuthenticationHelperTests
{
    private const string Password = "TestPassword123!";
    private const string BearerKey = "superSecretKey1234567890";
    private const string BearerKeyLong = "superSecretKey1234567890_superSecretKey1234567890";

    private JwtSettings _jwtSettings;
    private JwtSettings _jwtSettings2;

    [SetUp]
    public void Setup()
    {
        _jwtSettings = new JwtSettings
        {
            BearerKey = BearerKey,
            Issuer = "TestIssuer",
            ExpiresInSeconds = 3600
        };
        
        _jwtSettings2 = new JwtSettings
        {
            BearerKey = BearerKeyLong,
            Issuer = "TestIssuer",
            ExpiresInSeconds = 3600
        };
    }

    [Test]
    public void GenerateSalt_ShouldReturnValidSalt()
    {
        // Arrange
        const uint saltSize = 24;

        // Act
        var salt = typeof(AuthenticationHelper)
            .GetMethod("GenerateSalt", System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Static)?
            .Invoke(null, new object[] { saltSize }) as byte[];

        // Assert
        Assert.That(salt, Is.Not.Null);
        Assert.That(salt.Length, Is.EqualTo(saltSize));
    }

    [Test]
    public void GenerateHash_ShouldReturnValidHash()
    {
        // Arrange
        var salt = Convert.ToBase64String(new byte[24]);
        var password = Password;

        // Act
        var hash = AuthenticationHelper.GenerateHash(password, salt);

        // Assert
        Assert.NotNull(hash);
        Assert.IsNotEmpty(hash);
    }

    [Test]
    public void ProvideSaltAndHash_ShouldUpdateUserWithSaltAndHash()
    {
        // Arrange
        var user = new TestIdentityUser(Password);

        // Act
        user.ProvideSaltAndHash();

        // Assert
        Assert.Multiple(() =>
        {
            Assert.That(user.Salt, Is.Not.Null);
            Assert.That(user.PasswordHash, Is.Not.Empty);
            Assert.That(user.PasswordHash, Is.Not.EqualTo(Password));
        });
    }

    [Test]
    public void GenerateJwt_ShouldReturnNotValidToken()
    {
        // Arrange
        var claims = new[]
        {
            new Claim(ClaimTypes.Name, "TestUser"),
            new Claim(ClaimTypes.Role, "Admin")
        };

        var identity = AuthenticationHelper.AssembleClaimsIdentity(claims);

        string token = null!;
        
        // Act
        try
        {
            // to small length of BearerKey for HmacSha256Signature
            token = AuthenticationHelper.GenerateJwt(_jwtSettings, identity);
        }
        catch
        {
        }

        // Assert
        Assert.That(token, Is.Null);
    }

    
    [Test]
    public void GenerateJwt_ShouldReturnValidToken()
    {
        // Arrange
        var claims = new[]
        {
            new Claim(ClaimTypes.Name, "TestUser"),
            new Claim(ClaimTypes.Role, "Admin")
        };

        var identity = AuthenticationHelper.AssembleClaimsIdentity(claims);

        // Act
        var token = AuthenticationHelper.GenerateJwt(_jwtSettings2, identity);

        // Assert
        Assert.That(token, Is.Not.Null);
        Assert.That(token, Is.Not.Empty);
        Assert.That(token.Split('.').Length, Is.EqualTo(3)); // JWT has 3 parts (header, payload, signature)
    }

    [Test]
    public void AssembleClaimsIdentity_ShouldReturnValidIdentity()
    {
        // Arrange
        var claims = new[]
        {
            new Claim(ClaimTypes.Name, "TestUser"),
            new Claim(ClaimTypes.Role, "Admin")
        };

        // Act
        var identity = AuthenticationHelper.AssembleClaimsIdentity(claims);

        // Assert
        Assert.That(identity, Is.Not.Null);
        Assert.That(identity.Claims.Count(), Is.EqualTo(claims.Length));
    }
    
    /// <summary>
    /// Test implementation of IdentityUser for testing.
    /// </summary>
    public class TestIdentityUser : IdentityUser
    {
        public TestIdentityUser(string password) : base(password)
        {
        }
    }
}