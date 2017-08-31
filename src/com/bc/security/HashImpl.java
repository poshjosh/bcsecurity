package com.bc.security;

import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.util.Arrays;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;

/**
 * @author Chinomso Bassey Ikwuagwu on Dec 15, 2016 8:58:41 PM
 */
public class HashImpl implements Hash {

   /**
    * Each token produced by this class uses this identifier as a prefix.
    */
    private static final String PREFIX = "$31$";

   /**
    * The minimum recommended cost, used by default
    */
    private static final int DEFAULT_COST = 16;
    
    private static final int DEFAULT_SIZE = 128;

    private static final Pattern LAYOUT = Pattern.compile("\\$31\\$(\\d\\d?)\\$(.{43})");

    private final int cost;

    private final int size;
    
    private final SecureRandom random;
    
    private final SecretKeyFactory secretKeyFactory;

    public HashImpl(String algorithm) throws NoSuchAlgorithmException {
        this(algorithm, DEFAULT_COST, DEFAULT_SIZE);
    }

    /**
     * Create a Hash manager with a specified cost
     * 
     * @param algorithm
     * @param cost the exponential computational cost of hashing a password, 0 to 30
     * @param size
     * @throws java.security.NoSuchAlgorithmException
     */
    public HashImpl(String algorithm, int cost, int size) throws NoSuchAlgorithmException {
        validateCost(cost); 
        this.cost = cost;
        this.size = size;
        this.random = new SecureRandom();
        this.secretKeyFactory = SecretKeyFactory.getInstance(algorithm);
    }

    private int validateCost(int cost) {
        if ((cost & ~0x1F) != 0) {
            throw new IllegalArgumentException("cost: " + cost);
        }    
        return 1 << cost;
    }

    @Override
    public String getPrefix() {
        return PREFIX;
    }

    /**
     * Hash a password for storage.
     * 
     * @param password_plain
     * @return a secure authentication token to be stored for later authentication 
     * @throws java.security.spec.InvalidKeySpecException 
     */
    @Override
    public String hash(char[] password_plain) 
            throws InvalidKeySpecException {
        final byte[] salt = new byte[size / 8];
        random.nextBytes(salt);
        final byte[] dk = pbkdf2(password_plain, salt, 1 << cost);
        final byte[] hash = new byte[salt.length + dk.length];
        System.arraycopy(salt, 0, hash, 0, salt.length);
        System.arraycopy(dk, 0, hash, salt.length, dk.length);
        final Base64.Encoder enc = Base64.getUrlEncoder().withoutPadding();
        return PREFIX + cost + '$' + enc.encodeToString(hash);
    }

    /**
     * Authenticate with a password and a stored password token.
     * 
     * @param password_plain
     * @param stored_hash
     * @return true if the password and token match
     * @throws java.security.spec.InvalidKeySpecException
     */
    @Override
    public boolean authenticate(char[] password_plain, String stored_hash)
            throws InvalidKeySpecException {
      
        final Matcher m = LAYOUT.matcher(stored_hash);
        if (!m.matches()) {
            throw new IllegalArgumentException("Invalid stored_hash format");
        }    
        
        final int iterations = validateCost(Integer.parseInt(m.group(1)));
        final byte[] hash = Base64.getUrlDecoder().decode(m.group(2));
        final byte[] salt = Arrays.copyOfRange(hash, 0, size / 8);
        final byte[] check = pbkdf2(password_plain, salt, iterations);
        int zero = 0;
        for (int idx = 0; idx < check.length; ++idx) {
            zero |= hash[salt.length + idx] ^ check[idx];
        }    
        return zero == 0;
    }

    private byte[] pbkdf2(char[] password, byte[] salt, int iterations) 
            throws InvalidKeySpecException {
      
        final KeySpec spec = new PBEKeySpec(password, salt, iterations, size);
    
        return this.secretKeyFactory.generateSecret(spec).getEncoded();
    }
}