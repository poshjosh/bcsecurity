package com.bc.security;

/**
 * @author Chinomso Bassey Ikwuagwu on Dec 15, 2016 5:30:34 PM
 */
public class TestBCrypt2 {
    /**
      * A simple test case for the main method, verify that a pre-generated test hash verifies successfully
      * for the password it represents, and also generate a new hash and ensure that the new hash verifies
      * just the same.
      * @param args
      */
    public static void main(String[] args) {
        
        String test_passwd = "abcdefghijklmnopqrstuvwxyz";
        String test_hash = "$2a$06$.rCVZVOThsIa97pEDOxvGuRRgzG64bvtJ0938xuqzv18d3ZpQhstC";

        System.out.println("Testing BCrypt Password hashing and verification");
        System.out.println("Test password: " + test_passwd);
        System.out.println("Test stored hash: " + test_hash);
        System.out.println("Hashing test password...");
        System.out.println();

        String computed_hash = BCrypt.hashpw(test_passwd, BCrypt.gensalt()); 
        System.out.println("Test computed hash: " + computed_hash);
        System.out.println();
        System.out.println("Verifying that hash and stored hash both match for the test password...");
        System.out.println();

        String compare_test = BCrypt.checkpw(test_passwd, test_hash)
                ? "Passwords Match" : "Passwords do not match";
        String compare_computed = BCrypt.checkpw(test_passwd, computed_hash)
                ? "Passwords Match" : "Passwords do not match";

        System.out.println("Verify against stored hash:   " + compare_test);
        System.out.println("Verify against computed hash: " + compare_computed);

    }
}
