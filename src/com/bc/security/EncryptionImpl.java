package com.bc.security;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.SecretKeySpec;

/**
 * @author Chinomso Bassey Ikwuagwu on Dec 15, 2016 8:00:40 PM
 */
public class EncryptionImpl implements Encryption {

    /**
     * Cipher for encrypting
     */
    private final Cipher cipher;

    /**
     * Key for encrypting
     */
    private final SecretKeySpec secretKeySpec;
    
    private final BytesToHexConverter bytesToHexConverter;

    public EncryptionImpl(String algorithm, String encryptionKey, BytesToHexConverter bytesToHexConverter)
            throws NoSuchAlgorithmException, NoSuchPaddingException {
        
        this(algorithm, encryptionKey, 0, 16, bytesToHexConverter);
    }
    
    public EncryptionImpl(String algorithm, String encryptionKey, int i, int i1, BytesToHexConverter bytesToHexConverter)
            throws NoSuchAlgorithmException, NoSuchPaddingException {
        
        this.cipher = Cipher.getInstance(algorithm);

        //if the user has not set the password length correctly, just pad it out to required length
        while (encryptionKey.length() < i1) {
            encryptionKey += "-";
        }

        //prepare a key for use with the cipher
        byte[] keyBytes = encryptionKey.getBytes();
        assert keyBytes.length >= i1;

        this.secretKeySpec = new SecretKeySpec(keyBytes, i, i1, algorithm);
        
        this.bytesToHexConverter = bytesToHexConverter;
    }
    
    public EncryptionImpl(
            Cipher cipher, 
            SecretKeySpec secretKeySpec, 
            BytesToHexConverter bytesToHexConverter) {
        
        this.cipher = cipher;

        this.secretKeySpec = secretKeySpec;
        
        this.bytesToHexConverter = bytesToHexConverter;
    }
    
    /**
     * @param input The String to  encrypt
     * @return An encrypted String
     * @throws java.security.InvalidKeyException
     * @throws javax.crypto.IllegalBlockSizeException
     * @throws javax.crypto.BadPaddingException
     * @throws NullPointerException if the input String is null
     */
    @Override
    public synchronized final String encrypt(char [] input) 
            throws InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        
        if(input == null) {
            throw new NullPointerException("String to encrypt == null");
        }
        
        cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec);

        //encryptString the string
        byte[] encrypted = cipher.doFinal(new String(input).getBytes());
        String encryptedString = this.bytesToHexConverter.convert(encrypted);
        return encryptedString;
    }

    /**
     * @param input The String to  decrypt
     * @return An decrypted String
     * @throws java.security.InvalidKeyException
     * @throws javax.crypto.IllegalBlockSizeException
     * @throws javax.crypto.BadPaddingException
     * @throws NullPointerException if the input String is null
     */
    @Override
    public synchronized final char [] decrypt(String input) 
            throws InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        
        if(input == null) {
            throw new NullPointerException("String to decrypt == null");
        }

        cipher.init(Cipher.DECRYPT_MODE, secretKeySpec);

        //decryptString the string
        byte[] decrypted = cipher.doFinal(this.bytesToHexConverter.reverse(input));
        String decryptedString = new String(decrypted);
        return decryptedString.toCharArray();
    }
}
