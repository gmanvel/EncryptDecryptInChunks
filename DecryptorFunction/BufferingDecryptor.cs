using System;
using System.IO;
using System.Security.Cryptography;
using System.Threading.Tasks;
using Microsoft.Azure.WebJobs;
using Microsoft.Extensions.Logging;

namespace DecryptorFunction
{
    // Don't use with big blobs, most probably out of memory exception will be thrown
    public static class BufferingDecryptor
    {
        [FunctionName(nameof(BufferingDecryptor))]
        public static async Task Run(
            [BlobTrigger("diagnostics-encrypted/{name}", Connection = "StorageConnectionString")] byte[] encryptedBlob,
            [Blob("diagnostics-decrypted/{name}", FileAccess.Write, Connection = "StorageConnectionString")] Stream decryptedBlob,
            ILogger log)
        {
            using var rsa = RSA.Create();

            rsa.ImportRSAPrivateKey(
                Convert.FromBase64String("private key"),
                out var _);

            var aes = Aes.Create();

            aes.Mode = CipherMode.CBC;
            aes.Padding = PaddingMode.PKCS7;

            aes.IV = encryptedBlob[..16];

            var keyBuffer = encryptedBlob[16..272];

            aes.Key = rsa.Decrypt(keyBuffer, RSAEncryptionPadding.OaepSHA256);

            using (var memoryStream = new MemoryStream(encryptedBlob[272..]))
            using (var cryptoStream = new CryptoStream(memoryStream, aes.CreateDecryptor(aes.Key, aes.IV), CryptoStreamMode.Read))
            {
                await cryptoStream.CopyToAsync(decryptedBlob);
            }

            log.LogInformation("Decrypted the file");
        }
    }
}