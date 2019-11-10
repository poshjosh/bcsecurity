package com.bc.security;

import java.security.GeneralSecurityException;
import java.util.Properties;

/**
 * @author Chinomso Bassey Ikwuagwu on Jun 24, 2017 9:46:52 PM
 */
public class DecryptPassword {
    
    private static final Properties props = new Properties();

    public static void main(String [] args) {
        
        try{
            
            final DecryptPassword dp = new DecryptPassword();
            
            String email = "coolbuyng@gmail.com";
            System.out.println("NewsMinute. "+email+"\tPassword: " + 
                    new String(dp.decrypt(props.getProperty("encryptedpassword."+email))));
            
            email = "posh.bc@gmail.com";
            System.out.println("NewsMinute. "+email+"\tPassword: " + 
                    new String(dp.decrypt(props.getProperty("encryptedpassword."+email)))); 

        }catch(Exception e) {
            e.printStackTrace();
        }
    }

    private char [] decrypt(String val) throws GeneralSecurityException {
        
        return this.decrypt("AES", props.getProperty("encryption.key"), val);
    }
    
    private char [] decrypt(String algo, String enkey, String val) throws GeneralSecurityException {

        final Encryption encryption = SecurityProvider.DEFAULT.getEncryption(algo, enkey);

        return encryption.decrypt(val);
    }
}
