package com.bc.security;

import java.security.GeneralSecurityException;
import java.util.Calendar;
import java.util.StringTokenizer;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * @author Chinomso Bassey Ikwuagwu on Dec 15, 2016 7:30:04 PM
 */
public class SecurityTool {

    private static final AtomicInteger COUNTER = new AtomicInteger();

    public SecurityTool() { }
    
    public String generateUsername() {
        return generateUsername("user", 2015);
    }

    public String generateUsername(String prefix, int baseYear) {
        Calendar c = Calendar.getInstance();
        StringBuilder builder = new StringBuilder();
        builder.append(c.get(Calendar.YEAR)-baseYear);
        builder.append(c.get(Calendar.MONTH));
        builder.append(c.get(Calendar.DAY_OF_MONTH));
        builder.append(c.get(Calendar.HOUR));
        builder.append(c.get(Calendar.MINUTE));
        long n = Long.parseLong(builder.toString());
        return prefix + '_' + Long.toHexString(n) + (COUNTER.incrementAndGet());
    }
    
    public String getRandomUUID(final int outputSize) {
        
        String src = UUID.randomUUID().toString();
        src = src.replace("-", "");
        final int srcLen = src.length();
        
        if(outputSize > srcLen) return src;
        
        int randomOffset = (int)(Math.random() * srcLen);

        int end = randomOffset + outputSize;
        int offsetAtBeginning = -1;
        if(end > srcLen) {
            offsetAtBeginning = end - srcLen;
            end = srcLen;
        }

        String s = src.substring(randomOffset, end);
        if(offsetAtBeginning > 0) {
            s += src.substring(0, offsetAtBeginning);
        }
        
        return s;
    }

    public synchronized final String encryptCookieValues(Encryption enc, String val_1, String val_2) 
            throws GeneralSecurityException {
        String cookieString = String.format("%1s:::%2s", val_1, val_2);
        String encryptedCookieString = enc.encrypt(cookieString.toCharArray());
        return encryptedCookieString;
    }

    public synchronized final String[] decryptCookieValues(Encryption enc, String encryptedCookie) 
            throws GeneralSecurityException {
        String[] emailAndScreenName = new String[2];
        String decryptedCookie = new String(enc.decrypt(encryptedCookie));
        StringTokenizer tokenizer = new StringTokenizer(decryptedCookie, ":::");
        emailAndScreenName[0] = tokenizer.nextToken();
        emailAndScreenName[1] = tokenizer.nextToken();
        return emailAndScreenName;
    }
}
