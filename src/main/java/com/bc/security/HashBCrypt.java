package com.bc.security;

/**
 * @author Chinomso Bassey Ikwuagwu on Dec 15, 2016 5:55:22 PM
 */
public final class HashBCrypt implements Hash {
    
    private final int WORKLOAD;

    public HashBCrypt() {
        this(BCrypt.GENSALT_DEFAULT_LOG2_ROUNDS);
    }

    public HashBCrypt(int workload) {
        this.WORKLOAD = workload;
    }

    @Override
    public String getPrefix() {
        return BCrypt.PREFIX;
    }

    /**
     * This method can be used to generate a string representing an account password
     * suitable for storing in a database. It will be an OpenBSD-style crypt(3) formatted
     * hash string of length=60
     * The bcrypt WORKLOAD is specified in the above static variable, a value from 10 to 31.
     * A WORKLOAD of 12 is a very reasonable safe default as of 2013.
     * This automatically handles secure 128-bit salt generation and storage within the hash.
     * @param password_plain The account's plaintext password as provided during account creation,
     *			     or when changing an account's password.
     * @return String - a string of length 60 that is the bcrypt hashed password in crypt(3) format.
     */
    @Override
    public String hash(char[] password_plain) {
        
        final String salt = BCrypt.gensalt(WORKLOAD);
        
        String password_hashed = BCrypt.hashpw(new String(password_plain), salt);

        return(password_hashed);
    }

    /**
     * This method can be used to verify a computed hash from a plaintext (e.g. during a login
     * request) with that of a stored hash from a database. The password hash from the database
     * must be passed as the second variable.
     * @param password_plain The account's plaintext password, as provided during a login request
     * @param stored_hash The account's stored password hash, retrieved from the authorization database
     * @return boolean - true if the password matches the password of the stored hash, false otherwise
     */
    @Override
    public boolean authenticate(char[] password_plain, String stored_hash) {
        
        if(null == stored_hash || !stored_hash.startsWith(getPrefix())) {
            throw new java.lang.IllegalArgumentException("Invalid hash provided for comparison");
        }    

        final boolean password_verified = BCrypt.checkpw(new String(password_plain), stored_hash);

        return password_verified;
    }
}
