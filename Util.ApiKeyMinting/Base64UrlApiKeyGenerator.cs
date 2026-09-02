using System.Security.Cryptography;

namespace Util.ApiKeyMinting;

/// <summary>
/// Cryptographically random keys, rendered base64url so they survive headers, URLs and copy-paste unharmed.
/// </summary>
/// <remarks>
/// The prefix is part of the key and is therefore covered by the hash. It exists so secret scanners and log
/// redaction have something to match on, not as metadata to be parsed back out.
/// <para>
/// 32 random bytes is far past the point where hashing choice matters for guessing resistance, which is why a
/// fast hash is the right one here and a password KDF is not.
/// </para>
/// </remarks>
public sealed class Base64UrlApiKeyGenerator(string prefix = "", int entropyBytes = 32) : IApiKeyGenerator
{
    private readonly int _entropyBytes = entropyBytes >= 16
        ? entropyBytes
        : throw new ArgumentOutOfRangeException(nameof(entropyBytes), entropyBytes, "At least 16 bytes of entropy required.");

    /// <inheritdoc />
    public string Generate()
    {
        var bytes = RandomNumberGenerator.GetBytes(_entropyBytes);

        var encoded = Convert.ToBase64String(bytes)
            .TrimEnd('=')
            .Replace('+', '-')
            .Replace('/', '_');

        return prefix + encoded;
    }
}
