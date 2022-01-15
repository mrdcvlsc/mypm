/*
 * The MIT License
 *
 * Copyright 2022 mrdcvlsc.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */

package mypm;

import java.util.*;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

public class AES128
{
    public static void main(String[] Args)
    {
        try{
            String plainText = "this is a sensitive message";
            
            SecretKey AES256KEY = AES128.generateKey("RandomPasswordString", "RandomSaltString");
            IvParameterSpec randomIV = AES128.generateIV();
            String algorithm = "AES/CBC/PKCS5Padding";

            String cipherText = AES128.encrypt(algorithm, plainText, AES256KEY, randomIV);
            String recoverText = AES128.decrypt(algorithm, cipherText, AES256KEY, randomIV);
            
            System.out.println("plainText   : "+plainText+"\nlength = "+plainText.length()+"\n");
            System.out.println("cipherText  : "+cipherText+"\nlength = "+cipherText.length()+"\n");
            System.out.println("recoverText : "+recoverText+"\nlength = "+recoverText.length()+"\n");

            if(!recoverText.equals(plainText))
            {
                throw new AssertionError("AES ENCRYPTION-DECRYPTION : FAILED");
            }
            else
            {
                System.out.println("AES ENCRYPTION-DECRYPTION : PASSED");
            }
        } catch (Exception err)
        {
            err.printStackTrace();
        }
    }

    public static String keyToString(SecretKey key)
    {
        return Base64.getEncoder().encodeToString(key.getEncoded());
    }

    public static SecretKey generateKey() throws NoSuchAlgorithmException
    {
        KeyGenerator KEYRNG = KeyGenerator.getInstance("AES");
        KEYRNG.init(128);
        return KEYRNG.generateKey();
    }

    public static SecretKey generateKey(String password, String salt)
        throws
        InvalidKeySpecException,
            NoSuchAlgorithmException
    {        
        KeySpec PSWRDKEY = new PBEKeySpec(password.toCharArray(), salt.getBytes(), 65536, 128);
        SecretKeyFactory KEYGENSCHEME = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
        return new SecretKeySpec(KEYGENSCHEME.generateSecret(PSWRDKEY).getEncoded(), "AES");
    }
 
    public static IvParameterSpec generateIV()
    {
        byte[] IV = new byte[16];
        new SecureRandom().nextBytes(IV);
        return new IvParameterSpec(IV);
    }
    
    public static IvParameterSpec generateIV(byte[] IV)
    {
        IV = new byte[16];
        new SecureRandom().nextBytes(IV);
        return new IvParameterSpec(IV);
    }
    
    public static IvParameterSpec getIV(byte[] IV)
    {
        return new IvParameterSpec(IV);
    }
    
    public static String ByteToString(byte[] array)
    {
        return Base64.getEncoder().encodeToString(array);
    }
    
    public static byte[] StringToByte(String str)
    {
        return Base64.getDecoder().decode(str);
    }

    public static String encrypt(String encryptionScheme, String plainText, SecretKey key, IvParameterSpec IV)
        throws
            NoSuchAlgorithmException,
            InvalidAlgorithmParameterException,
            InvalidKeyException,
            NoSuchPaddingException,
            BadPaddingException,
            IllegalBlockSizeException
    {
        
        Cipher AESENCRYPT = Cipher.getInstance(encryptionScheme);
        AESENCRYPT.init(Cipher.ENCRYPT_MODE, key, IV);
        byte[] cipherText = AESENCRYPT.doFinal(plainText.getBytes());
        return Base64.getEncoder().encodeToString(cipherText);
    }
 
    public static String decrypt(String decryptionScheme, String cipherText, SecretKey key, IvParameterSpec IV)
        throws
            NoSuchAlgorithmException,
            InvalidAlgorithmParameterException,
            InvalidKeyException,
            NoSuchPaddingException,
            BadPaddingException,
            IllegalBlockSizeException
    {
        
        Cipher AESDECRYPT = Cipher.getInstance(decryptionScheme);
        AESDECRYPT.init(Cipher.DECRYPT_MODE, key, IV);
        byte[] recoveredText = AESDECRYPT.doFinal(Base64.getDecoder().decode(cipherText));
        return new String(recoveredText);
    }
}