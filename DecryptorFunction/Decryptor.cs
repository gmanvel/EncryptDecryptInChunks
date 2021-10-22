using System;
using System.IO;
using System.Security.Cryptography;
using System.Threading.Tasks;
using Microsoft.Azure.WebJobs;
using Microsoft.Extensions.Logging;

namespace DecryptorFunction
{
    public static class Decryptor
    {
        [FunctionName(nameof(Decryptor))]
        public static async Task Run(
            [BlobTrigger("diagnostics-encrypted/{name}", Connection = "StorageConnectionString")] Stream encryptedBlob,
            [Blob("diagnostics-decrypted/{name}", FileAccess.Write, Connection = "StorageConnectionString")] Stream decryptedBlob,
            ILogger log)
        {
            using var rsa = RSA.Create();

            rsa.ImportRSAPrivateKey(
                Convert.FromBase64String("private_key"),
                out var _);

            var aes = Aes.Create();

            aes.Mode = CipherMode.CBC;
            aes.Padding = PaddingMode.PKCS7;

            var ivBuffer = new byte[16];
            while (await encryptedBlob.ReadAsync(ivBuffer, 0, ivBuffer.Length) != ivBuffer.Length)
            { }

            aes.IV = ivBuffer;

            var keyBuffer = new byte[256];
            while (await encryptedBlob.ReadAsync(keyBuffer, 0, keyBuffer.Length) != keyBuffer.Length) ;

            aes.Key = rsa.Decrypt(keyBuffer, RSAEncryptionPadding.OaepSHA256);

            using (var cryptoStream = new CryptoStream(encryptedBlob, aes.CreateDecryptor(aes.Key, aes.IV), CryptoStreamMode.Read))
            {
                await cryptoStream.CopyToAsync(decryptedBlob);
            }

            log.LogInformation("Decrypted the file");
        }
    }
}
