# bcsecurity
Encryption, Decryption, Hashing, Authentication tools

# Example usages

```java
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
```
