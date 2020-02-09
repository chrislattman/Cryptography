package crypto;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.Scanner;

/**
 * ElGamal Signature Scheme in pure Java.
 * 
 * Whenever setting up a cryptosystem that uses the Discrete Log Problem, use
 * a prime p of the form 4k + 3 that is also a safe prime (p = 2q + 1, q is 
 * also a prime).
 * 
 * @author Chris Lattman
 *
 */
public class ElGamalSignature {
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
     * The ElGamal Signature Scheme.
     * 
     * The prime modulus p is given above in hex, which has a generator 
     * alpha = 2.
     * 
     * Public:  (p, alpha, beta)
     * Private: (a, k)
     * 
     * @param args not used
     */
    public static void main(String[] args) {
        /*
         * Prime p and generator alpha are described above. They are public.
         */
        BigInteger p = new BigInteger(prime, 16);
        BigInteger alpha = BigInteger.TWO;
        SecureRandom random = new SecureRandom();
        System.out.println("Public parameters:");
        System.out.println("p = " + p.toString(16));
        System.out.println("alpha = " + alpha.toString(16));
        
        /*
         * a is randomly chosen. It is a private parameter.
         * 
         * The range of a is [1, p - 2].
         * 
         * If a is not in the acceptable range, a new value for a is chosen 
         * until it falls in the valid range.
         */
        BigInteger a = new BigInteger(2048, random);
        while (a.compareTo(BigInteger.ONE) < 0 ||
               a.compareTo(p.subtract(BigInteger.TWO)) > 0) {
            a = new BigInteger(2048, random);
        }
        
        /*
         * Compute beta = alpha^a (mod p). This is a public parameter.
         */
        BigInteger beta = alpha.modPow(a, p);
        System.out.println("beta = " + beta.toString(16));
        
        /*
         * The following loop gives the user the opportunity to sign a
         * message using the created instance of ElGamal signature scheme.
         * 
         * The signed message takes the form (m, r, s), where m is the 
         * message and r and s are signature values.
         */
        Scanner scanner = new Scanner(System.in);
        System.out.println();
        System.out.print("Do you want to sign a message? y/n: ");
        String answer = scanner.next().toLowerCase();
        while (answer.contains("y")) {
            /*
             * The message m is obtained from standard input and is then
             * encoded using the getBytes() String method (UTF-8).
             */
            System.out.print("Enter a message to be signed: ");
            scanner.nextLine();
            String message = scanner.nextLine();
            byte[] mbytes = message.getBytes();
            BigInteger m = new BigInteger(mbytes);
            
            /*
             * k is randomly chosen in Z*_p-1, the group of multiplicative 
             * inverses mod p - 1. It is a private parameter.
             * 
             * The range of k is [2, p - 2].
             * 
             * If k is not in the acceptable range, a new value for k is chosen 
             * until it falls in the valid range.
             * 
             * Since k must be invertible under multiplication mod p - 1, it 
             * suffices to choose k to be a probable prime less than p - 1.
             * 
             * It is important to generate a new k, and thus r value for each
             * message. Otherwise ElGamal signatures is vulnerable to targeted
             * forgeries by revealing a, the private parameter. This allows an
             * attacker to compute s for any message with random k.
             */
            BigInteger k = BigInteger.probablePrime(2048, random);
            while (k.compareTo(BigInteger.TWO) < 0 ||
                   k.compareTo(p.subtract(BigInteger.TWO)) > 0) {
                k = BigInteger.probablePrime(2048, random);
            }
            
            /*
             * r, the first signature value, is computed as 
             * r = alpha^k (mod p)
             * 
             * s, the last signature value, is computed as
             * s = k^(-1) * (ar - m) (mod p - 1)
             */
            BigInteger r = alpha.modPow(k, p);
            BigInteger ar = a.multiply(r);
            BigInteger pminus1 = p.subtract(BigInteger.ONE);
            BigInteger kInv = k.modInverse(pminus1);
            BigInteger s = ar.subtract(m).multiply(kInv).mod(pminus1);
            System.out.println("Signed message:");
            System.out.println("m = " + message);
            System.out.println("r = " + r.toString(16));
            System.out.println("s = " + s.toString(16));
            
            /*
             * The following code verifies that the signature provided is 
             * a valid signature.
             * 
             * Since s = k^(-1) * (ar - m) (mod p - 1), 
             * ks = ar - m (mod p - 1) and thus
             * ar = m + ks (mod p - 1)
             * 
             * The verification condition is beta^r = alpha^m * r^s (mod p)
             * 
             * This works because beta^r = (alpha^a)^r (mod p)
             *                           = alpha^(ar) (mod p)
             *                           = alpha^(m + ks) (mod p)
             *                           = alpha^m * alpha^(ks) (mod p)
             *                           = alpha^m * (alpha^k)^s (mod p)
             *                           = alpha^m * r^s (mod p)
             */
            BigInteger am_rs = alpha.modPow(m, p).multiply(r.modPow(s, p));
            if (beta.modPow(r, p).equals(am_rs.mod(p))) {
                System.out.println("Signature is verified.");
            }
            else {
                // the following line should never be called
                System.out.println("Signature is not verified.");
            }
            System.out.println();
            System.out.print("Do you want to sign a message? y/n: ");
            answer = scanner.next().toLowerCase();
        }
        scanner.close();
    }

}
