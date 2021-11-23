package crypto;

import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.Scanner;
import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * Discrete Logarithm Integrated Encryption Scheme (IES) in pure Java. It
 * combines the Diffie-Hellman key exchange with AES, where the AES secret key
 * is generated using SHA-256.
 * 
 * Whenever setting up a cryptosystem that uses the Discrete Logarithm 
 * Problem, use a prime p of the form 4k + 3 that is also a safe prime 
 * (p = 2q + 1, q is also a prime).
 * 
 * @author Chris Lattman
 */
public class IES {
    /*
     * 2048-bit prime obtained from https://www.ietf.org/rfc/rfc3526.txt
     * A generator of the prime is 2.
     */
    public static String prime = "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628"
        + "B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF951"
        + "9B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44"
        + "C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE64"
        + "9286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5"
        + "F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9"
        + "804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC0"
        + "7A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D226189"
        + "8FA051015728E5A8AACAA68FFFFFFFFFFFFFFFF";

    /**
     * The Integrated Encryption Scheme. IES uses a cryptographic hash 
     * function to create a secret key and a block cipher to encrypt messages.
     * This implementation of IES uses SHA-256 and AES/CBC/PKCS5Padding 
     * (256-bit AES).
     * 
     * The prime modulus p is given above in hex, which has a generator 
     * alpha = 2.
     * 
     * Public:  (p, alpha, g, h)
     * Private: (a, b, s)
     * 
     * @param args not used
     * @throws Exception a whole host of exceptions can be thrown, although
     *                   they are all non-issues in this implementation
     */
    public static void main(String[] args) throws Exception {
        /*
         * Alice and Bob publicly agree to use prime p and generator alpha.
         */
        BigInteger p = new BigInteger(prime, 16);
        BigInteger alpha = BigInteger.TWO;
        System.out.println("Public parameters:");
        System.out.println("p = " + p.toString(16));
        System.out.println("alpha = " + alpha.toString(16));
        
        /*
         * In this example, Alice sends a message to Bob, who set up this
         * instance of IES.
         * 
         * Alice generates a randomly and Bob generates b randomly. These are
         * both secret.
         * 
         * The range of a and b is [2, p - 2].
         * 
         * If a or b are not in the acceptable range, new values of a and b
         * are chosen until they fall in the valid range.
         */
        SecureRandom random = new SecureRandom();
        BigInteger a = new BigInteger(2048, random);
        BigInteger b = new BigInteger(2048, random);
        while (a.compareTo(BigInteger.TWO) < 0 || 
               a.compareTo(p.subtract(BigInteger.TWO)) > 0 ||
               b.compareTo(BigInteger.TWO) < 0 ||
               b.compareTo(p.subtract(BigInteger.TWO)) > 0) {
            a = new BigInteger(2048, random);
            b = new BigInteger(2048, random);
        }
        
        /*
         * Alice computes g = alpha^a (mod p) whereas Bob computes 
         * h = alpha^b (mod p). These are public paramaters, so Alice can see
         * Bob's public key (and vice-versa).
         */
        BigInteger g = alpha.modPow(a, p);
        BigInteger h = alpha.modPow(b, p);
        System.out.println("g = " + g.toString(16));
        System.out.println("h = " + h.toString(16));
        
        /*
         * Alice would then compute h^a = (alpha^b)^a = alpha^(ab) (mod p), 
         * the shared secret. Bob can also generate this shared secret by 
         * computing g^b = (alpha^a)^b = alpha^(ab) (mod p).
         */
        BigInteger secret = h.modPow(a, p);
        
        /*
         * hash is an instance of SHA-256, the cryptographic hash function 
         * used by IES
         */
        MessageDigest hash = MessageDigest.getInstance("SHA-256");
        
        /*
         * Alice computes the secret key k for AES by hashing the shared 
         * secret = alpha^(ab) (mod p). Bob can do the same, since he knows 
         * the shared secret as well.
         */
        byte[] kbytes = hash.digest(secret.toByteArray());
        SecretKeySpec k = new SecretKeySpec(kbytes, "AES");
        
        /*
         * This is the message to be sent from Alice to Bob.
         */
        System.out.print("Enter the message for Alice to encrypt: ");
        Scanner scanner = new Scanner(System.in);
        String message = scanner.nextLine();
        scanner.close();
        
        /*
         * cipher is an instance of 256-bit AES with CBC mode and PKCS5 
         * padding, the block cipher used by IES
         * 
         * It is initialized to encrypt data using the secret key k and an
         * initialization vector iv of {0} for AES's CBC mode.
         */
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        byte[] iv = new byte[16];
        IvParameterSpec ivspec = new IvParameterSpec(iv);
        cipher.init(Cipher.ENCRYPT_MODE, k, ivspec);
        
        /*
         * The message is encrypted with AES and sent to Bob in ciphertext 
         * base64.
         * 
         * The Base64 class is used due to padding.
         */
        byte[] ciphertextbytes = cipher.doFinal(message.getBytes());
        String base64 = Base64.getEncoder().encodeToString(ciphertextbytes);
        System.out.println("Ciphertext (in base64): " + base64);
        
        /*
         * Bob then decrypts the message using the secret key k and the 
         * initialization vector iv (which were generated earlier).
         * 
         * Here, the same block cipher is reused for decryption.
         */
        cipher.init(Cipher.DECRYPT_MODE, k, ivspec);
        byte[] cipherbytes = Base64.getDecoder().decode(base64);
        byte[] plaintextbytes = cipher.doFinal(cipherbytes);
        String plaintext = new String(plaintextbytes);
        System.out.println("Plaintext: " + plaintext);
    }

}
