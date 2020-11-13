using System;
using System.IO;
using System.Security.Cryptography;
using System.Linq;
using System.Text;
using System.Collections.Generic;
using Spire.Pdf;

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
            byte[] key = new SHA256CryptoServiceProvider().ComputeHash(Encoding.UTF8.GetBytes("37E1}*+?O%A6Ws6@"));
            // IV?
            byte[] XVI = new byte[16];
            AESEncryptionService ser = new AESEncryptionService();

            Console.WriteLine("Enter app name:");
            string appName = Console.ReadLine();
            string booksPath = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), appName, "Books");
            string[] fileEntriesarr = Directory.GetFiles(booksPath);
            var fileEntries = new List<string>(fileEntriesarr);
            fileEntries.RemoveAll(x => x.Contains("__"));
            foreach (string fileEntry in fileEntries)
            {
                string passwordFileName = Path.GetFileName(fileEntry);
                if (passwordFileName.StartsWith("_"))
                {
                    string s = File.ReadAllText(fileEntry);
                    string password = Encoding.UTF8.GetString(ser.Decrypt(Convert.FromBase64String(s), key, XVI));
                    string fileName = passwordFileName.Replace("_", "");

                    string pdfPath = Path.Join(Path.GetDirectoryName(fileEntry), fileName);
                    PdfDocument pdf = new PdfDocument(pdfPath, password);
                    // Deprecated with no available replacement. :))
                    pdf.Security.UserPassword = string.Empty;

                    //Saves the document, adds some watermark which is, eh, whatever.
                    pdf.SaveToFile(fileName + "_NoPassword.pdf");
                    Console.WriteLine(fileName + " 's Password removed!");
                }
            }
        }
    }
}
