using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;

namespace Common
{
    public class EncryptionLibrary
    {
        public static byte[] AES_Encrypt(byte[] bytesToBeEncrypted, byte[] passwordBytes)
        {
            byte[] encryptedBytes = null;
            // Set your salt here, change it to meet your flavor:  
            // The salt bytes must be at least 8 bytes.  
            byte[] saltBytes = new byte[] { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
            using (MemoryStream ms = new MemoryStream())
            {
                using (AesManaged aes = new AesManaged())
                {
                    aes.KeySize = 128;
                    aes.BlockSize = 128;
                    var key = new Rfc2898DeriveBytes(passwordBytes, saltBytes, 1000);
                    aes.Key = key.GetBytes(aes.KeySize / 8);
                    aes.IV = key.GetBytes(aes.BlockSize / 8);
                    aes.Mode = CipherMode.CBC;
                    aes.Padding = PaddingMode.None;
                    using (var cs = new CryptoStream(ms, aes.CreateEncryptor(), CryptoStreamMode.Write))
                    {
                        cs.Write(bytesToBeEncrypted, 0, bytesToBeEncrypted.Length);
                        cs.Close();
                    }
                    encryptedBytes = ms.ToArray();
                }
            }
            return encryptedBytes;
        }
        public static byte[] AES_Decrypt(byte[] bytesToBeDecrypted, byte[] passwordBytes)
        {
            try
            {
                byte[] decryptedBytes = null;
                // Set your salt here, change it to meet your flavor:  
                // The salt bytes must be at least 8 bytes.  
                byte[] saltBytes = new byte[] { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
                using (MemoryStream ms = new MemoryStream())
                {
                    using (AesManaged AES = new AesManaged())
                    {
                        AES.KeySize = 128;
                        AES.BlockSize = 128;
                        var key = new Rfc2898DeriveBytes(passwordBytes, saltBytes, 1000);
                        AES.Key = key.GetBytes(AES.KeySize / 8);
                        AES.IV = key.GetBytes(AES.BlockSize / 8);
                        AES.Mode = CipherMode.CBC;
                        AES.Padding = PaddingMode.None;
                        using (var cs = new CryptoStream(ms, AES.CreateDecryptor(), CryptoStreamMode.Write))
                        {
                            cs.Write(bytesToBeDecrypted, 0, bytesToBeDecrypted.Length);
                            cs.Close();
                        }
                        decryptedBytes = ms.ToArray();
                    }
                }
                return decryptedBytes;
            }
            catch (Exception ex)
            {
                throw ex;
            }
        }
        public static string EncryptText(string input, string password = "E6t187^D43%F")
        {
            try
            {
                // Get the bytes of the string  
                byte[] bytesToBeEncrypted = Encoding.UTF8.GetBytes(input);
                byte[] passwordBytes = Encoding.UTF8.GetBytes(password);
                // Hash the password with SHA256  
                //passwordBytes = SHA256.Create().ComputeHash(passwordBytes);
                byte[] bytesEncrypted = AES_Encrypt(bytesToBeEncrypted, passwordBytes);
                string result = Convert.ToBase64String(bytesEncrypted);
                return result;
            }
            catch (Exception)
            {
                throw;
            }
        }
        public static string DecryptText(string input, string password = "E6t187^D43%F")
        {
            try
            {
                // Get the bytes of the string  
                byte[] bytesToBeDecrypted = Convert.FromBase64String(input);
                byte[] passwordBytes = Encoding.UTF8.GetBytes(password);
                //passwordBytes = SHA256.Create().ComputeHash(passwordBytes);
                byte[] bytesDecrypted = AES_Decrypt(bytesToBeDecrypted, passwordBytes);
                string result = Encoding.UTF8.GetString(bytesDecrypted);
                return result;
            }
            catch (Exception)
            {
                throw;
            }
        }
    }
}