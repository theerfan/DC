using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;

namespace DecryptMirKh
{
    internal class AESEncryptionService
    {
        public byte[] Encrypt(byte[] input, byte[] key, byte[] iv)
        {
            RijndaelManaged rijndaelManaged = new RijndaelManaged();
            rijndaelManaged.KeySize = 256;
            rijndaelManaged.BlockSize = 128;
            rijndaelManaged.Padding = PaddingMode.PKCS7;
            rijndaelManaged.Key = key;
            rijndaelManaged.IV = iv;
            ICryptoTransform encryptor = rijndaelManaged.CreateEncryptor(rijndaelManaged.Key, rijndaelManaged.IV);
            using (MemoryStream memoryStream = new MemoryStream())
            {
                using (CryptoStream cryptoStream = new CryptoStream((Stream)memoryStream, encryptor, CryptoStreamMode.Write))
                    cryptoStream.Write(input, 0, input.Length);
                return memoryStream.ToArray();
            }
        }

        public byte[] Decrypt(byte[] input, byte[] key, byte[] iv)
        {
            RijndaelManaged rijndaelManaged = new RijndaelManaged();
            rijndaelManaged.KeySize = 256;
            rijndaelManaged.BlockSize = 128;
            rijndaelManaged.Mode = CipherMode.CBC;
            rijndaelManaged.Padding = PaddingMode.PKCS7;
            rijndaelManaged.Key = key;
            rijndaelManaged.IV = iv;
            ICryptoTransform decryptor = rijndaelManaged.CreateDecryptor();
            using (MemoryStream memoryStream = new MemoryStream())
            {
                using (CryptoStream cryptoStream = new CryptoStream((Stream)memoryStream, decryptor, CryptoStreamMode.Write))
                    cryptoStream.Write(input, 0, input.Length);
                return memoryStream.ToArray();
            }
        }
    }

    class Program
    {
        static void Main(string[] args)
        {
            byte[] IV = new byte[16];
            AESEncryptionService ser = new AESEncryptionService();
            byte[] key = new SHA256CryptoServiceProvider().ComputeHash(Encoding.UTF8.GetBytes("37E1}*+?O%A6Ws6@"));
            string s = "jSF3fJxh+n+7c+jZTN/DtO5oBIEdGaHLNFNWgoRzrxPp2658OdLsCwhlOCcosSgb";
            string pass = Encoding.UTF8.GetString(ser.Decrypt(Convert.FromBase64String(s), key, IV));
            Console.WriteLine(pass);
        }
    }
}
