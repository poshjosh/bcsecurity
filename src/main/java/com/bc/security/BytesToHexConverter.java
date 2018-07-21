/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */

package com.bc.security;

/**
 * @author Chinomso Bassey Ikwuagwu on Apr 12, 2018 10:04:10 PM
 */
public interface BytesToHexConverter {

    /**
     * Used to convert the encrypted bytes into chars to send over the web
     * @param bytes
     * @return
     */
    String convert(byte[] bytes);

    /**
     * Used to convert an encoded string into a byte array for de-encryping
     * @param hex
     * @return
     */
    byte[] reverse(String hex);

}
