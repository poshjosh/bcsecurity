package com.bc.security;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Objects;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.SecretKeySpec;

/**
 * @author Chinomso Bassey Ikwuagwu on Dec 15, 2016 8:00:40 PM
 */
public class EncryptionImpl implements Encryption {

    private final String algorithm;
    
    /**
     * Key for encrypting
     */
    private final SecretKeySpec secretKeySpec;
    
    private final BytesToHexConverter bytesToHexConverter;

    public EncryptionImpl(String algorithm, String encryptionKey)
            throws NoSuchAlgorithmException, NoSuchPaddingException {
        
        this(algorithm, encryptionKey, 0, 16, new BytesToHexConverterImpl());
    }
    
    public EncryptionImpl(String algorithm, String encryptionKey, int i, int i1, BytesToHexConverter bytesToHexConverter)
            throws NoSuchAlgorithmException, NoSuchPaddingException {
        
        this.algorithm = algorithm;
        
        this.setCipher(Cipher.getInstance(algorithm));

        //if the user has not set the password length correctly, just pad it out to required length
        while (encryptionKey.length() < i1) {
            encryptionKey += "-";
        }

        //prepare a key for use with the cipher
        byte[] keyBytes = encryptionKey.getBytes();
        assert keyBytes.length >= i1;

        this.secretKeySpec = new SecretKeySpec(keyBytes, i, i1, algorithm);
        
        this.bytesToHexConverter = Objects.requireNonNull(bytesToHexConverter);
    }
    
    public EncryptionImpl(
            Cipher cipher, 
            SecretKeySpec secretKeySpec, 
            BytesToHexConverter bytesToHexConverter) {

        this.algorithm = Objects.requireNonNull(cipher.getAlgorithm());
        
        this.setCipher(cipher);

        this.secretKeySpec = Objects.requireNonNull(secretKeySpec);
        
        this.bytesToHexConverter = Objects.requireNonNull(bytesToHexConverter);
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
        
        Objects.requireNonNull(input, "String to encrypt == null");
        
        final Cipher cipher = this.getCipher();
        
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
        
        Objects.requireNonNull(input, "String to decrypt == null");

        final Cipher cipher = this.getCipher();
        
        cipher.init(Cipher.DECRYPT_MODE, secretKeySpec);

        //decryptString the string
        byte[] decrypted = cipher.doFinal(this.bytesToHexConverter.reverse(input));
        String decryptedString = new String(decrypted);
        return decryptedString.toCharArray();
    }
    
    private transient Cipher _c;
    private void setCipher(Cipher cipher) {
        this._c = cipher;
    }
    public Cipher getCipher() {
        if(_c == null) {
            try{
                _c = Cipher.getInstance(algorithm);
            }catch(NoSuchAlgorithmException | NoSuchPaddingException e) {
                throw new RuntimeException(e);
            }
        }
        return _c;
    }
}
