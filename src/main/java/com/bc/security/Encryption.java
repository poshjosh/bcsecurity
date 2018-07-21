package com.bc.security;

import java.security.GeneralSecurityException;

/**
 * @author Chinomso Bassey Ikwuagwu on Dec 15, 2016 7:47:41 PM
 */
public interface Encryption {

    String encrypt(char [] input) throws GeneralSecurityException;
    
    char [] decrypt(String input) throws GeneralSecurityException;
}
