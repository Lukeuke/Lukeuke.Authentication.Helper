namespace Lukeuke.Authentication.Jwt;

/// <summary>
/// Base class for Identity, containing properties for password management.
/// </summary>
public abstract class IdentityUser
{
    protected IdentityUser(string password)
    {
        PasswordHash = password;
    }
    
    /// <summary>
    /// The hashed representation of the user's password. 
    /// </summary>
    public string PasswordHash { get; set; }

    /// <summary>
    /// The salt used for password hashing. 
    /// This can be null if the password has not yet been hashed.
    /// </summary>
    public string? Salt { get; set; }
}