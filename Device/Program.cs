using System;
using System.IO;
using System.Security.Cryptography;
using System.Threading.Tasks;

namespace Device
{
    class Program
    {
        static async Task Main(string[] args)
        {
            using var rsa = RSA.Create();

            rsa.ImportRSAPublicKey(
                Convert.FromBase64String("public_key"),
                out var _);

            var aes = Aes.Create();
            aes.Mode = CipherMode.CBC;
            aes.Padding = PaddingMode.PKCS7;

            aes.GenerateKey();
            aes.GenerateIV();

            using (var dataStream = File.OpenRead("file to encrypt"))
            using (var secretFileStream = File.Create("encrypted file"))
            {
                await secretFileStream.WriteAsync(aes.IV);
                await secretFileStream.WriteAsync(rsa.Encrypt(aes.Key, RSAEncryptionPadding.OaepSHA256));

                using (var cryptoStream = new CryptoStream(secretFileStream, aes.CreateEncryptor(aes.Key, aes.IV), CryptoStreamMode.Write))
                {
                    await dataStream.CopyToAsync(cryptoStream);
                }
            }
        }
    }
}
