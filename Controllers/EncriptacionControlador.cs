using Microsoft.AspNetCore.Mvc;
using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;

public class EncriptacionControlador : Controller
{
    public IActionResult Encryption()
    {
        return View("~/Views/Encrypt/encryption.cshtml");
    }

    [HttpPost]
    public IActionResult Encryption(string plainText)
    {
        if (string.IsNullOrEmpty(plainText))
        {
            ViewBag.Error = "El texto a encriptar no puede estar vacío.";
            return View("~/Views/Encrypt/encryption.cshtml");
        }

        string encryptedText = EncryptionHelper.Encrypt(plainText);
        ViewBag.EncryptedText = encryptedText;
        return View("~/Views/Encrypt/encryption.cshtml");
    }

    public IActionResult Desencrypt()
    {
        return View("~/Views/Encrypt/desencrypt.cshtml");
    }

    [HttpPost]
    public IActionResult Desencrypt(string encryptedText)
    {
        if (string.IsNullOrEmpty(encryptedText))
        {
            ViewBag.Error = "El texto a desencriptar no puede estar vacío.";
            return View("~/Views/Encrypt/desencrypt.cshtml");
        }

        try
        {
            string decryptedText = EncryptionHelper.Decrypt(encryptedText);
            ViewBag.DecryptedText = decryptedText;
        }
        catch (Exception ex)
        {
            ViewBag.Error = "Error al desencriptar el texto: " + ex.Message;
        }

        return View("~/Views/Encrypt/desencrypt.cshtml");
    }
    [HttpPost]
    public IActionResult DesencryptPost(string encryptedText)
    {
        if (string.IsNullOrEmpty(encryptedText))
        {
            ViewBag.Error = "El texto a desencriptar no puede estar vacío.";
            return View("~/Views/Encrypt/desencrypt.cshtml");
        }

        try
        {
            string decryptedText = EncryptionHelper.Decrypt(encryptedText);
            ViewBag.DecryptedText = decryptedText;
        }
        catch (Exception ex)
        {
            ViewBag.Error = "Error al desencriptar el texto: " + ex.Message;
        }

        return View("~/Views/Encrypt/desencrypt.cshtml");
    }

}

public static class EncryptionHelper
{
    private static readonly string Key = "minombre_esjonat";

    public static string Encrypt(string plainText)
    {
        using (Aes aesAlg = Aes.Create())
        {
            aesAlg.Key = Encoding.UTF8.GetBytes(Key);
            aesAlg.IV = new byte[16]; 

            ICryptoTransform encryptor = aesAlg.CreateEncryptor(aesAlg.Key, aesAlg.IV);

            using (MemoryStream msEncrypt = new MemoryStream())
            {
                using (CryptoStream csEncrypt = new CryptoStream(msEncrypt, encryptor, CryptoStreamMode.Write))
                using (StreamWriter swEncrypt = new StreamWriter(csEncrypt))
                {
                    swEncrypt.Write(plainText);
                }
                return Convert.ToBase64String(msEncrypt.ToArray());
            }
        }
    }

    public static string Decrypt(string cipherText)
    {
        using (Aes aesAlg = Aes.Create())
        {
            aesAlg.Key = Encoding.UTF8.GetBytes(Key);
            aesAlg.IV = new byte[16]; 

            ICryptoTransform decryptor = aesAlg.CreateDecryptor(aesAlg.Key, aesAlg.IV);

            using (MemoryStream msDecrypt = new MemoryStream(Convert.FromBase64String(cipherText)))
            using (CryptoStream csDecrypt = new CryptoStream(msDecrypt, decryptor, CryptoStreamMode.Read))
            using (StreamReader srDecrypt = new StreamReader(csDecrypt))
            {
                return srDecrypt.ReadToEnd();
            }
        }
    }


}
