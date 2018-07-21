package com.bc.security;

import java.security.GeneralSecurityException;
import java.util.Arrays;
import java.util.UUID;
import static junit.framework.TestCase.assertEquals;

/**
 * @author Chinomso Bassey Ikwuagwu on Dec 15, 2016 5:52:25 PM
 */
public class Main {

    public static void main(String [] args) {
        
        try{
            
            final char[] pass = "3rfUmx-?".toCharArray();
            
            final SecurityProvider sy = SecurityProvider.DEFAULT;

            final Hash bycrpt = sy.getHash(SecurityProvider.BCRYPT);

            final String pass_hash = bycrpt.hash(pass);

            System.out.println("Bycrpt hashed password: "+pass_hash);

            final boolean authenticated_bycrpt = bycrpt.authenticate(pass, pass_hash);
            
            System.out.println("Authenticated Bycrpt: "+authenticated_bycrpt);

            final String encryptionKey = UUID.randomUUID().toString();

            final Encryption aes = sy.getEncryption(SecurityProvider.AES, encryptionKey);

            final String pass_enc = aes.encrypt(pass);
            
            System.out.println("AES encrypted password: "+pass_enc);
            
            final char [] pass_dec = aes.decrypt(pass_enc);
            
            final boolean authenticated_aes = Arrays.equals(pass_dec, pass);
            
            System.out.println("Authenticated AES: "+authenticated_aes);
            
            SecurityToolOld syTool = new SecurityToolOld("AES", encryptionKey);
            
            final String pass_enc2 = syTool.encrypt(new String(pass));

            System.out.println("AES encrypted password 2: "+pass_enc2);
            
            assertEquals(pass_enc, pass_enc2);
            
            final String pass_dec2 = syTool.decrypt(pass_enc2);  
            
            assertEquals(new String(pass_dec), pass_dec2);
            
            System.out.println("Authenticated AES 2: "+authenticated_aes);
            
        }catch(GeneralSecurityException e) {
         
            e.printStackTrace();
        }
    }
}
