/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */

package com.bc.security;

/**
 * @author Chinomso Bassey Ikwuagwu on Dec 15, 2016 7:53:24 PM
 */
public class BytesToHexConverter {

    /**
     * The chars that will be used in the textual representation of the encoded bytes
     */
    private static final String DIGITS = "0123456789abcdef";

    public BytesToHexConverter() { }

    /**
     * Used to convert the encrypted bytes into chars to send over the web
     * @param bytes
     * @return 
     */
    public String convert(byte[] bytes) {
        StringBuilder builder = new StringBuilder();
        for (byte b : bytes) {
            int v = b & 0xff;
            builder.append(DIGITS.charAt(v >> 4));
            builder.append(DIGITS.charAt(v & 0xf));
        }
        return builder.toString();
    }

    /**
     * Used to convert an encoded string into a byte array for de-encryping
     * @param hex
     * @return 
     */
    public byte[] reverse(String hex) {
        byte[] data = new byte[hex.length() / 2];
        for (int dataIndex = 0; dataIndex < data.length; dataIndex++) {
            char charA = hex.charAt(dataIndex * 2);
            char charB = hex.charAt(dataIndex * 2 + 1);
            int i = (byte) 0xff;
            i = i & ((byte) DIGITS.indexOf(charA));
            i = i << 4;
            i = i | ((byte) DIGITS.indexOf(charB));
            data[dataIndex] = (byte) i;
        }
        return data;
    }
}
