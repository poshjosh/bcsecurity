package com.bc.security;

import java.security.GeneralSecurityException;

/**
 * @author Chinomso Bassey Ikwuagwu on Dec 15, 2016 5:45:13 PM
 */
public interface SecurityProvider {

    String BCRYPT = "BCrypt";
    String PBKDF2WITHHMACSHA1 = "PBKDF2WithHmacSHA1";
    String AES = "AES";
    
    Hash getHash() throws GeneralSecurityException;
    
    Hash getHash(String algorithm) throws GeneralSecurityException;
    
    Encryption getEncryption(String encryptionKey) throws GeneralSecurityException;
    
    Encryption getEncryption(String algorithm, String encryptionKey) throws GeneralSecurityException;
    
    SecurityProvider DEFAULT = new InternalImpl();
    
    public static final class InternalImpl implements SecurityProvider {
        
        private InternalImpl() {}
        
        @Override
        public Hash getHash() throws GeneralSecurityException {
            return this.getHash(BCRYPT);
        }
        
        @Override
        public Hash getHash(String algorithm) throws GeneralSecurityException {
            Hash output;
            switch(algorithm) {
                case BCRYPT:
                    output = new HashBCrypt(); break;
                default:
                    output = new HashImpl(algorithm); break;
            }
            return output;
        }

        @Override
        public Encryption getEncryption(String encryptionKey) throws GeneralSecurityException {
            return this.getEncryption(AES, encryptionKey);
        }

        @Override
        public Encryption getEncryption(String algorithm, String encryptionKey) throws GeneralSecurityException {
            final int [] lengths = this.getLengths(algorithm);
            Encryption output = new EncryptionImpl(algorithm, encryptionKey, lengths[0], lengths[1], new BytesToHexConverterImpl());
            return output;
        }
        
        private int [] getLengths(String algorithm) {
            final int [] output;
            switch(algorithm) {
                case AES:
                    output = new int[]{0, 16}; break;
                default:
                    throw new IllegalArgumentException("Unexpected security algorithm: "+algorithm);
            }
            return output;
        }
    }
}
