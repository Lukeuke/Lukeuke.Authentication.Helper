## Examples of use

```csharp
/// <summary>
/// Represents an application-specific implementation of an identity user.
/// </summary>
public class User : IdentityUser
{
    /// <summary>
    /// The username of the user.
    /// </summary>
    public string Username { get; set; } = string.Empty;

    /// <summary>
    /// The email address of the user.
    /// </summary>
    public string Email { get; set; } = string.Empty;
}
```

```csharp
var user = new User("myRawPassword")
{
    Username = "JohnDoe",
    Email = "john.doe@example.com"
};

// Salt and hash the password
user.ProvideSaltAndHash();
```