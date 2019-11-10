package com.bc.security;

import java.security.GeneralSecurityException;
import java.util.Arrays;
import java.util.UUID;
import static junit.framework.TestCase.fail;
import org.junit.Test;

/**
 * @author Chinomso Bassey Ikwuagwu on Dec 15, 2016 5:52:25 PM
 */
public class GlobalTest {

    private transient final char[] pass = "3rfUmx-?".toCharArray();
            
    @Test
    public void testHash(){
        System.out.println("testHash");
        
        try{
            
            final SecurityProvider sy = SecurityProvider.DEFAULT;

            final Hash bycrpt = sy.getHash(SecurityProvider.BCRYPT);

            final String pass_hash = bycrpt.hash(pass);

            System.out.println("Bycrpt hashed password: "+pass_hash);

            final boolean passed = bycrpt.authenticate(pass, pass_hash);
            
            System.out.println("Authenticated Bycrpt: "+passed);
            
            if(!passed) {
                fail("BCrypt test failed");
            }
            
        }catch(GeneralSecurityException e) {
         
            e.printStackTrace();
        }
    }

    @Test
    public void testEncryption(){
        System.out.println("testEncryption");
        
        try{
            
            final SecurityProvider sy = SecurityProvider.DEFAULT;

            final String encryptionKey = UUID.randomUUID().toString();

            final Encryption aes = sy.getEncryption(SecurityProvider.AES, encryptionKey);

            final String pass_enc = aes.encrypt(pass);
            
            System.out.println("AES encrypted password: "+pass_enc);
            
            final char [] pass_dec = aes.decrypt(pass_enc);
            
            final boolean passed = Arrays.equals(pass_dec, pass);
            
            System.out.println("Authenticated AES: "+passed);
            
            if(!passed) {
                fail("BCrypt test failed");
            }
        }catch(GeneralSecurityException e) {
         
            e.printStackTrace();
        }
    }
}
