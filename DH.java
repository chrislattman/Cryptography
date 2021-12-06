package crypto;

import java.math.BigInteger;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

/**
 * Dicrete Logarithm Diffie-Hellman (DH) Key Exchange in pure Java.
 * 
 * Whenever setting up a cryptosystem that uses the Discrete Logarithm 
 * Problem, use a prime p of the form 4k + 3 that is also a safe prime 
 * (p = 2q + 1, q is also a prime).
 * 
 * DH is vulnerable to a man-in-the-middle attack. If Eve maintains two
 * separate key exchanges with Alice and Bob, she can intercept messages
 * sent between Alice and Bob, decrypting then re-encrypting messages. 
 * However, Eve must always maintain these key exchanges; otherwise, her 
 * presence becomes known to Alice and Bob. The STS Protocol mitigates such
 * an attack.
 * 
 * @author Chris Lattman
 */
public class DH {
    /*
     * 2048-bit prime obtained from https://www.ietf.org/rfc/rfc3526.txt
     * A generator of the prime is 2.
     */
    private static final String prime = "FFFFFFFFFFFFFFFFC90FDAA22168C234"
        + "C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404"
        + "DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E"
        + "7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C"
        + "4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8"
        + "FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C35"
        + "4E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B27"
        + "83A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515"
        + "D2261898FA051015728E5A8AACAA68FFFFFFFFFFFFFFFF";

    /**
     * The Diffie-Hellman key exchange (DH).
     * 
     * The prime modulus p is given above in hex, which has a generator 
     * alpha = 2.
     * 
     * Public:  (p, alpha, g, h)
     * Private: (a, b, s)
     * 
     * @param args not used
     * @throws NoSuchAlgorithmException non-issue
     */
    public static void main(String[] args) throws NoSuchAlgorithmException {
        /*
         * Alice and Bob publicly agree to use prime p and generator alpha.
         */
        BigInteger p = new BigInteger(prime, 16);
        BigInteger alpha = BigInteger.TWO;
        System.out.println("Public parameters:");
        System.out.println("p = " + p.toString(16));
        System.out.println("alpha = " + alpha.toString(16));
        
        /*
         * Alice generates a randomly and Bob generates b randomly. These are
         * both secret.
         * 
         * The range of a and b is [2, p - 2].
         * 
         * If a or b are not in the acceptable range, new values of a and b
         * are chosen until they fall in the valid range.
         */
        SecureRandom random = SecureRandom.getInstanceStrong();
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
         * h = alpha^b (mod p).
         * 
         * Alice sends g to Bob, who sends h to Alice.
         */
        BigInteger g = alpha.modPow(a, p);
        BigInteger h = alpha.modPow(b, p);
        System.out.println("g = " + g.toString(16));
        System.out.println("h = " + h.toString(16));
        
        /*
         * Alice would then compute h^a = (alpha^b)^a = alpha^(ab) (mod p).
         * Bob would compute g^b = (alpha^a)^b = alpha^(ab) (mod p).
         * 
         * These two values are equal, and thus s = g^b (mod p) = h^a (mod p)
         * is the shared secret key.
         */
        BigInteger secretA = g.modPow(b, p);
        BigInteger secretB = h.modPow(a, p);
        
        /*
         * This statement ensures the user that g^b (mod p) = h^a (mod p), 
         * hence Alice and Bob have the same secret key.
         */
        if (secretA.equals(secretB)) {
            System.out.println("g^b (mod p) == h^a (mod p)");
        }
        else {
            // the following line should never be called
            System.out.println("g^b (mod p) =/= h^a (mod p)");
        }
    }
}
