package com.bc.security;

import java.security.GeneralSecurityException;

/**
 * @author Chinomso Bassey Ikwuagwu on Dec 15, 2016 5:42:12 PM
 */
public interface Hash {
    
    String getPrefix();
    
    String hash(char [] password_plain) throws GeneralSecurityException;
    
    boolean authenticate(char [] password_plain, String stored_hash) throws GeneralSecurityException;
}
