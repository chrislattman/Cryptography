package crypto;

import java.math.BigInteger;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Scanner;

/**
 * ElGamal Signature Scheme in pure Java.
 * 
 * Whenever setting up a cryptosystem that uses the Discrete Logarithm 
 * Problem, use a prime p of the form 4k + 3 that is also a safe prime 
 * (p = 2q + 1, q is also a prime).
 * 
 * @author Chris Lattman
 *
 */
public class ElGamalSignature {
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
     * The ElGamal Signature Scheme.
     * 
     * The prime modulus p is given above in hex, which has a generator 
     * alpha = 2.
     * 
     * Public:  (p, alpha, beta)
     * Private: (a, k)
     * 
     * @param args not used
     * @throws NoSuchAlgorithmException non-issue
     */
    public static void main(String[] args) throws NoSuchAlgorithmException {
        /*
         * Prime p and generator alpha are described above. They are public.
         */
        BigInteger p = new BigInteger(prime, 16);
        BigInteger alpha = BigInteger.TWO;
        System.out.println("Public parameters:");
        System.out.println("p = " + p.toString(16));
        System.out.println("alpha = " + alpha.toString(16));
        
        /*
         * a is randomly chosen in Z mod p-1, the group of multiplicative 
         * inverses mod p - 1. Therefore a is relatively prime to p - 1.
         * It is a private parameter.
         * 
         * Since a must be invertible under multiplication mod p - 1, it
         * suffices to choose k to be a probable prime less than p - 1.
         */
        SecureRandom random = SecureRandom.getInstanceStrong();
        BigInteger a = BigInteger.probablePrime(2048, random);
        while (a.compareTo(p.subtract(BigInteger.ONE)) >= 0) {
            a = BigInteger.probablePrime(2048, random);
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
             * k is randomly chosen in Z mod p-1, the group of multiplicative 
             * inverses mod p - 1. Therefore k is relatively prime to p - 1.
             * It is a private parameter.
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
            while (k.compareTo(p.subtract(BigInteger.ONE)) >= 0) {
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
             * The following code verifies that the signed message provided is
             * valid.
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
