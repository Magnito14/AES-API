# AES API

API Wrapper For The Aes Class.

## Usage

**Creating API Object:**
```cs
AdvancedEncryptionStandard aes = new AdvancedEncryptionStandard();
```

**Encrypting:**
```cs
string plainText = "This is my secret message";
string password = "password123";
string salt = "randomSalt";
```

```cs
string encryptedText = aes.Encrypt(plainText, password, salt);
Console.WriteLine($"Encrypted text: {encryptedText}.");
```

**Decrypting:**
```cs
string decryptedText = aes.Decrypt(encryptedText, password, salt);
Console.WriteLine($"Decrypted text: {decryptedText}.");
```
