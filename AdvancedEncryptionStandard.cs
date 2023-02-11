using System.Security.Cryptography;
using System.Text;

namespace Cryptography;

public class AdvancedEncryptionStandard {
    #region Public Methods
    /// <summary>
    /// Takes plain text, password, and salt as input and returns the encrypted string.
    /// </summary>
    /// <param name="plainText"></param>
    /// <param name="password"></param>
    /// <param name="salt"></param>
    public string Encrypt(string plainText, string password, string salt) {
        byte[] plainBytes = Encoding.UTF8.GetBytes(plainText);

        GetKeyAndIVBytes(password, salt, out byte[] keyBytes, out byte[] ivBytes);
        return EncryptOrDecrypt(plainBytes, keyBytes, ivBytes, CryptoStreamMode.Write);
    }

    /// <summary>
    /// Takes encrypted text, password, and salt as input and returns the decrypted string.
    /// </summary>
    /// <param name="encryptedText"></param>
    /// <param name="password"></param>
    /// <param name="salt"></param>
    public string Decrypt(string encryptedText, string password, string salt) {
        byte[] encryptedBytes = Convert.FromBase64String(encryptedText);

        GetKeyAndIVBytes(password, salt, out byte[] keyBytes, out byte[] ivBytes);
        return EncryptOrDecrypt(encryptedBytes, keyBytes, ivBytes, CryptoStreamMode.Read);
    }
    #endregion

    #region Private Methods
    /// <summary>
    /// Performs the actual encryption or decryption using AES and the "CryptoStream" class.
    /// </summary>
    /// <param name="inputBytes"></param>
    /// <param name="keyBytes"></param>
    /// <param name="ivBytes"></param>
    /// <param name="mode"></param>
    private static string EncryptOrDecrypt(byte[] inputBytes,
                                           byte[] keyBytes,
                                           byte[] ivBytes,
                                           CryptoStreamMode mode) {
        using MemoryStream memoryStream = new();
        using Aes aes = Aes.Create();

        aes.Key = keyBytes;
        aes.IV = ivBytes;

        using CryptoStream cryptoStream = new(memoryStream, mode is CryptoStreamMode.Write
            ? aes.CreateEncryptor()
            : aes.CreateDecryptor(), mode);

        cryptoStream.Write(inputBytes, 0, inputBytes.Length);
        return mode is CryptoStreamMode.Write
            ? Convert.ToBase64String(memoryStream.ToArray())
            : new StreamReader(cryptoStream).ReadToEnd();
    }

    /// <summary>
    /// derives the key and IV bytes used in AES encryption and decryption using the password and salt.
    /// Uses the "Rfc2898DeriveBytes" class for key derivation.
    /// </summary>
    /// <param name="password"></param>
    /// <param name="salt"></param>
    /// <param name="keyBytes"></param>
    /// <param name="ivBytes"></param>
    private static void GetKeyAndIVBytes(string password,
                                         string salt,
                                         out byte[] keyBytes,
                                         out byte[] ivBytes) {
        byte[] passwordBytes = Encoding.UTF8.GetBytes(password);
        byte[] saltBytes = Encoding.UTF8.GetBytes(salt);

        using Rfc2898DeriveBytes rfc2898 = new(passwordBytes, saltBytes, 1000);

        keyBytes = rfc2898.GetBytes(32);
        ivBytes = rfc2898.GetBytes(16);
    }
    #endregion
}
