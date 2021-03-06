using System.Collections;
using System.Collections.Generic;
using UnityEngine;
using System;
using System.IO;
using System.Text;
using System.Security.Cryptography;
using System;
using System.Security.Cryptography;
using System.Text;
using System.IO;
using System.Collections.Generic;
using System.Text.RegularExpressions;




public class AES256
{
    private static AES256 g_aes256 = null;
    public static void createInst(byte[] pwd){  
        bool needCreate = false;
        if (g_aes256 == null) {
            needCreate = true;
        }else{
            if (pwd.Length != g_aes256.m_passphrase.Length) {
                needCreate = true;
            }else{
                for (int i = 0; i < pwd.Length; i++) {
                    if (pwd[i] != g_aes256.m_passphrase[i]) {
                        needCreate = true;
                        break;
                    }
                }
            }               
        }
        if (needCreate) {
            g_aes256 = new AES256 (pwd);
        }
    }
    public static AES256 getInst(){
        return g_aes256;
    }

    public static string bytes2Str(byte[] ary){
        string ret = "";
        for(int i=0; i<ary.Length;i++){
            ret += ary [i].ToString()+",";

        }
        return ret;
    }

    public const string SALT_STR = "Yd";
    public const int BlockSize = 16;
    public const int KeyLen = 32;
    public const int IvLen = 16;

    private byte[] m_key;
    private byte[] m_iv;
    private byte[] m_salt;
    private byte[] m_passphrase;
    private byte[] m_flag = new byte[1]{0};

    private MD5 m_md5;
    private RijndaelManaged m_aes;
    private ICryptoTransform m_encryptor;
    private ICryptoTransform m_decryptor;

    private AES256(byte[] pwd){
        this.Init (pwd);
    }

    private void Init(byte[] pwd){      
        m_key = new byte[KeyLen];
        m_iv = new byte[IvLen];
        m_md5 = MD5.Create();
        m_salt = new byte[4];
        for (int i = 0; i < m_salt.Length; i++) {
            if (i > pwd.Length - 1) {
                m_salt [i] = 0;
            } else {
                m_salt [i] = pwd [i];
            }
        }
        m_passphrase = new byte[pwd.Length];
        Array.Copy (pwd, m_passphrase, pwd.Length);
        DeriveKeyAndIv ();

        m_aes = new RijndaelManaged ();
        m_aes.BlockSize = BlockSize * 8;
        m_aes.Mode = CipherMode.CBC;
        m_aes.Padding = PaddingMode.PKCS7;
        m_aes.Key = m_key;
        m_aes.IV = m_iv;

        m_encryptor = m_aes.CreateEncryptor(m_aes.Key, m_aes.IV);
        m_decryptor = m_aes.CreateDecryptor(m_aes.Key, m_aes.IV);
        Debug.Log ("Aes256 init, salt:" + bytes2Str (m_salt) + ", key:" + bytes2Str (m_key) + ", iv:" + bytes2Str (m_iv));
    }

    private void resetVars(){
        for (int i = 0; i < m_iv.Length; i++) {
            m_iv [i] = 0;
        }
        for (int i = 0; i < m_key.Length; i++) {
            m_key [i] = 0;
        }
    }

    protected void DeriveKeyAndIv()
    {
        resetVars();

        byte[] dx = new byte[] {};
        byte[] salted = new byte[] {};

        for (int i = 0; i < (KeyLen + IvLen / 16); i++) {
            dx = Concat(Concat(dx, m_passphrase), m_salt);
            dx = m_md5.ComputeHash(dx);
            salted = Concat(salted, dx);
        }

        Array.Copy(salted, 0, m_key, 0, KeyLen);
        Array.Copy(salted, KeyLen, m_iv, 0, IvLen);
    }

    public byte[] Encrypt(byte[] bary)
    {
        string text = Encoding.UTF8.GetString (bary);
        byte[] encrypted;
        using (var msEncrypt = new MemoryStream())
        {
            using (var csEncrypt = new CryptoStream(msEncrypt, m_encryptor, CryptoStreamMode.Write))
            {
                using (var swEncrypt = new StreamWriter(csEncrypt))
                {
                    swEncrypt.Write(text);
                }

                encrypted = msEncrypt.ToArray();
            }
        }

        return Concat(Concat(SALT_STR, m_salt), encrypted);
    }

    public byte[] Decrypt(byte[] ct)
    {
        if (ct == null || ct.Length <= 0) {
            return null;
        }

        byte[] salted = new byte[SALT_STR.Length];
        Array.Copy(ct, 0, salted, 0, SALT_STR.Length);

        if (Encoding.UTF8.GetString(salted) != SALT_STR) {
            return null;
        }

        int offset = SALT_STR.Length + m_salt.Length +1;
        byte[] cipherText = new byte[ct.Length - offset];
        Array.Copy(ct, offset, cipherText, 0, ct.Length - offset);

        string decrypted;

        using (var msDecrypt = new MemoryStream(cipherText))
        {
            using (var csDecrypt = new CryptoStream(msDecrypt, m_decryptor, CryptoStreamMode.Read))
            {
                using (var srDecrypt = new StreamReader(csDecrypt))
                {
                    decrypted = srDecrypt.ReadToEnd();
                }
            }
        }

        byte[] ret = Encoding.UTF8.GetBytes( decrypted );

        if (ct [SALT_STR.Length] == 1) {
            byte[] newSalt = new byte[m_salt.Length];
            Array.Copy (ct, SALT_STR.Length + 1, newSalt, 0, newSalt.Length);
            this.Init (newSalt);
        }

        return ret;
    }


    private static byte[] Concat(byte[] a, byte[] b)
    {
        byte[] output = new byte[a.Length + b.Length];

        for (int i = 0; i < a.Length; i++)
            output[i] = a[i];
        for (int j = 0; j < b.Length; j++)
            output[a.Length+j] = b[j];

        return output;
    }

    private static byte[] Concat(string a, byte[] b)
    {
        return Concat(Encoding.UTF8.GetBytes(a), b);
    }
}

public class RsaEncrypt
{
    static string s_pub;
    static string c_pri;

    public static void init()
    {
        byte[] bt = File.ReadAllBytes("./pem/client_private.xml");
        c_pri = Encoding.UTF8.GetString(bt);
        Debug.Log("c_pri:" + c_pri);

        byte[] bt1 = File.ReadAllBytes("./pem/server_public.xml");
        s_pub = Encoding.UTF8.GetString(bt1);
        Debug.Log("s_pub:" + s_pub);
    }
    
    public static string GetCPri()
    {
        return c_pri;
    }

    public static string GetSPub()
    {
        return s_pub;
    }

    public static void RSAGenerateKey(ref string privateKey, ref string publicKey)
    {
        RSACryptoServiceProvider rsa = new RSACryptoServiceProvider();
        privateKey = rsa.ToXmlString(true);
        publicKey = rsa.ToXmlString(false);
    }

    public static byte[] RSAEncrypt(byte[] data, string publicKey)
    {
        RSACryptoServiceProvider rsa = new RSACryptoServiceProvider();
        rsa.FromXmlString(publicKey);
        byte[] encryptData = rsa.Encrypt(data, true);
        return encryptData;
    }

    public static byte[] RSADecrypt(byte[] data, string privateKey)
    {
        RSACryptoServiceProvider rsa = new RSACryptoServiceProvider();
        rsa.FromXmlString(privateKey);
        byte[] decryptData = rsa.Decrypt(data, true);
        if (decryptData.Length == 4) {
            AES256.createInst (decryptData);
        }
        return decryptData;
    }

    public static byte[] EncryptStringToBytes_Aes(string plainText, byte[] Key)
    {
        byte[] encrypted;
        byte[] IV;

        using (Aes aesAlg = Aes.Create())
        {
            aesAlg.Key = Key;

            aesAlg.GenerateIV();
            IV = aesAlg.IV;

            aesAlg.Mode = CipherMode.CBC;

            var encryptor = aesAlg.CreateEncryptor(aesAlg.Key, aesAlg.IV);

            using (var msEncrypt = new MemoryStream())
            {
                using (var csEncrypt = new CryptoStream(msEncrypt, encryptor, CryptoStreamMode.Write))
                {
                    using (var swEncrypt = new StreamWriter(csEncrypt))
                    {
                        swEncrypt.Write(plainText);
                    }
                    encrypted = msEncrypt.ToArray();
                }
            }
        }

        var combinedIvCt = new byte[IV.Length + encrypted.Length];
        Array.Copy(IV, 0, combinedIvCt, 0, IV.Length);
        Array.Copy(encrypted, 0, combinedIvCt, IV.Length, encrypted.Length);

        return combinedIvCt;

    }

    public static string DecryptStringFromBytes_Aes(byte[] cipherTextCombined, byte[] Key)
    {

        string plaintext = null;

        using (Aes aesAlg = Aes.Create())
        {
            aesAlg.Key = Key;

            byte[] IV = new byte[aesAlg.BlockSize/8];
            byte[] cipherText = new byte[cipherTextCombined.Length - IV.Length];

            Array.Copy(cipherTextCombined, IV, IV.Length);
            Array.Copy(cipherTextCombined, IV.Length, cipherText, 0, cipherText.Length);

            aesAlg.IV = IV;

            aesAlg.Mode = CipherMode.CBC;

            ICryptoTransform decryptor = aesAlg.CreateDecryptor(aesAlg.Key, aesAlg.IV);

            using (var msDecrypt = new MemoryStream(cipherText))
            {
                using (var csDecrypt = new CryptoStream(msDecrypt, decryptor, CryptoStreamMode.Read))
                {
                    using (var srDecrypt = new StreamReader(csDecrypt))
                    {

                        plaintext = srDecrypt.ReadToEnd();
                    }
                }
            }

        }

        return plaintext;

    }
}

