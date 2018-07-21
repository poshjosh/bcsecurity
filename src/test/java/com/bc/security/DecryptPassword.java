package com.bc.security;

import java.security.GeneralSecurityException;

/**
 * @author Chinomso Bassey Ikwuagwu on Jun 24, 2017 9:46:52 PM
 */
public class DecryptPassword {

    public static void main(String [] args) {
        
        try{
            
            final DecryptPassword dp = new DecryptPassword();
            
System.out.println("NewsMinute. coolbuyng@gmail.com\tPassword: " + new String(dp.decrypt("9bd0edf2adde512ef0467804a9bafd73")));
            
System.out.println("NewsMinute. posh.bc@gmail.com\tPassword: " + new String(dp.decrypt("099f42975a9855afe91efd705236941b"))); 

        }catch(Exception e) {
            e.printStackTrace();
        }
    }

    private char [] decrypt(String val) throws GeneralSecurityException {
        
        return this.decrypt("AES", "AcIcvwW2MU4sJkvBx103m6gKsePm", val);
    }
    
    private char [] decrypt(String algo, String enkey, String val) throws GeneralSecurityException {

        final Encryption encryption = SecurityProvider.DEFAULT.getEncryption(algo, enkey);

        return encryption.decrypt(val);
    }
}
