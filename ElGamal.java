package crypto;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.Scanner;

/**
 * ElGamal cryptosystem in pure Java. It is based on the Diffie-Hellman
 * key exchange.
 * 
 * Whenever setting up a cryptosystem that uses the Discrete Logarithm 
 * Problem, use a prime p of the form 4k + 3 that is also a safe prime 
 * (p = 2q + 1, q is also a prime).
 * 
 * @author Chris Lattman
 */
public class ElGamal {
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
     * The ElGamal cryptosystem.
     * 
     * The prime modulus p is given above in hex, which has a generator 
     * alpha = 2.
     * 
     * Public:  (p, alpha, h)
     * Private: (b, a)
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
         * a is a private parameter chosen randomly such that 1 < a < q
         * 
         * The range of b is [2, p - 2].
         * 
         * If b is not in the acceptable range, a new value for b is chosen 
         * until it falls in the valid range.
         */
        BigInteger b = new BigInteger(2048, random);
        while (b.compareTo(BigInteger.TWO) < 0 ||
               b.compareTo(p.subtract(BigInteger.TWO)) > 0) {
            b = new BigInteger(2048, random);
        }
        
        /*
         * Compute h = alpha^b (mod p). This is a public parameter.
         */
        BigInteger h = alpha.modPow(b, p);
        System.out.println("h = " + h.toString(16));
        
        /*
         * The following loop gives the user the opportunity to use the newly
         * created instance of ElGamal to encrypt or decrypt messages.
         * 
         * Ciphertexts take on the form (c1, c2), where c1 = g and
         * c2 = m * s (mod p), explained below.
         */
        Scanner scanner = new Scanner(System.in);
        System.out.println();
        System.out.print("Do you want to encrypt or decrypt a message? "
            + "y/n: ");
        String answer = scanner.next().toLowerCase();
        while (answer.contains("y")) {
            System.out.print("Encrypt or decrypt? ");
            String direction = scanner.next().toLowerCase();
            if (direction.equals("encrypt")) {
                /*
                 * The message m is obtained from standard input and is then
                 * encoded using the getBytes() String method (UTF-8).
                 */
                System.out.print("Enter the message: ");
                scanner.nextLine();
                String plaintext = scanner.nextLine();
                BigInteger m = new BigInteger(plaintext.getBytes());
                
                /*
                 * The sender generates a randomly. This is secret.
                 * 
                 * The range of a is [2, p - 2].
                 * 
                 * If a is not in the acceptable range, a new value of a is 
                 * chosen until it falls in the valid range.
                 */
                BigInteger a = new BigInteger(2048, random);
                while (a.compareTo(BigInteger.TWO) < 0 || 
                    a.compareTo(p.subtract(BigInteger.TWO)) > 0) {
                    a = new BigInteger(2048, random);
                }
                
                /*
                 * The sender computes g = alpha^a (mod p). This is c1.
                 * 
                 * The sender also computes s = h^a (mod p), which is used
                 * to compute c2 = m * s (mod p).
                 * 
                 * c1 (which is g) and c2 are public and sent to the 
                 * cryptosystem's owner.
                 * 
                 * s is secret, but can be determined if one knows the
                 * plaintext to a particular ciphertext. It is crucial that
                 * a, and thus s, is newly generated for each message.
                 */
                BigInteger g = alpha.modPow(a, p); // c1 = g
                BigInteger s = h.modPow(a, p);
                BigInteger c2 = m.multiply(s).mod(p);
                System.out.println("Ciphertext:");
                System.out.println("c1 = " + g.toString(16));
                System.out.println("c2 = " + c2.toString(16));
            }
            else if (direction.equals("decrypt")) {
                System.out.println("Enter c1 and c2 (in hex):");
                System.out.print("c1 = ");
                String c1val = scanner.next();
                System.out.print("c2 = ");
                String c2val = scanner.next();
                BigInteger c1 = new BigInteger(c1val, 16);
                BigInteger c2 = new BigInteger(c2val, 16);
                
                /*
                 * The decryption process is as follows:
                 * 
                 * 1. compute s = c1^b (mod p)
                 * 2. compute m = c2 * s^(-1) (mod p)
                 * 3. decode m using the toByteArray() BigInteger method to 
                 *    obtain the plaintext message
                 */
                BigInteger s = c1.modPow(b, p);
                BigInteger m = c2.multiply(s.modInverse(p)).mod(p);
                String plaintext = new String(m.toByteArray());
                System.out.println("Plaintext: " + plaintext);
            }
            else {
                System.out.println("Invalid input.");
            }
            System.out.println();
            System.out.print("Do you want to encrypt or decrypt a "
                + "message? y/n: ");
            answer = scanner.next().toLowerCase();
        }
        scanner.close();
    }

}
