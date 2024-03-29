package crypto;

import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Scanner;

/**
 * Three RSA signature schemes in pure Java.
 * 
 * The first scheme, RSA signatures, signs messages without a hash function.
 * 
 * The second scheme, RSA blind signatures, signs a message without knowing
 * the message's contents.
 * 
 * The third scheme, RSA-SHA, signs messages like RSA signatures but uses the
 * SHA-256 cryptographic hash function.
 * 
 * @author Chris Lattman
 */
public class RSASignature {
    
    /**
     * Entry function for RSA signature functions.
     * 
     * @param args not used
     */
    public static void main(String[] args) {
        Scanner scanner = new Scanner(System.in);
        System.out.print("Would you like to sign a message? y/n: ");
        String answer = scanner.next();
        while (answer.contains("y")) {
            System.out.println("You can choose from three RSA signatures "
                + "schemes:");
            System.out.println("1. RSA signatures");
            System.out.println("2. RSA blind signatures");
            System.out.println("3. RSA-SHA");
            System.out.print("Enter the number of the signature scheme you "
                + "would like to use: ");
            String schemeInput = scanner.next().replaceAll("[^0-9]", "");
            try {
                int scheme = Integer.parseInt(schemeInput);
                if (scheme == 1) {
                    rsaSignatures(scanner, false, false);
                }
                else if (scheme == 2) {
                    rsaSignatures(scanner, false, true);
                }
                else if (scheme == 3) {
                    rsaSignatures(scanner, true, false);
                }
                else {
                    System.out.println("Invalid input.");
                }
            }
            catch (Exception e) {
                System.out.println("Invalid input.");
            }
            System.out.println();
            System.out.print("Would you like to sign another message? y/n: ");
            answer = scanner.next();
        }
        scanner.close();
    }

    /**
     * In all instances of RSA signatures, primes p and q are chosen and kept
     * private, as well as d and phi(n), whereas n and e are published.
     * 
     * RSA-SHA simply applies a hash function to the encoded message.
     * 
     * RSA blind signatures applies a mask to a message so that the owner of
     * the cryptosystem cannot read the plaintext message, but can still sign
     * it.
     * 
     * Public:  (n, e)
     * Private: (p, q, d, phi(n))
     * 
     * @param scanner standard input from the main function
     * @param hash if true, a hash function is used
     * @param blind if true, blind signatures are used
     * @throws NoSuchAlgorithmException non-issue (SHA-256 is defined)
     */
    private static void rsaSignatures(Scanner scanner, boolean hash, 
        boolean blind) throws NoSuchAlgorithmException {
        System.out.print("Would like you use custom primes, i.e. "
            + "Sophie Germain/safe primes? y/n: ");
        String answer = scanner.next().toLowerCase();
        SecureRandom random = SecureRandom.getInstanceStrong();
        BigInteger p, q;
        
        if (answer.contains("y")) {
            System.out.println("Enter p and q (in hex):");
            System.out.print("p: ");
            String prime_p = scanner.next();
            System.out.print("q: ");
            String prime_q = scanner.next();
            p = new BigInteger(prime_p, 16);
            q = new BigInteger(prime_q, 16);
        }
        else {
            /*
             * Two distinct 2048-bit probable primes are chosen. In the rare
             * case that p = q, a new prime q is chosen until they are no 
             * longer equal.
             */
            p = BigInteger.probablePrime(2048, random);
            q = BigInteger.probablePrime(2048, random);
            while (p.equals(q)) {
                q = BigInteger.probablePrime(2048, random);
            }
        }
        
        /*
         * n = p * q is computed and e is set to 65537, a commonly used Fermat
         * prime in RSA. They are both public parameters.
         * 
         * The following private parameters are computed:
         * 
         * phi(n) = phi(p) * phi(q) = (p - 1) * (q - 1)
         * 
         * d = e^(-1) (mod phi(n))
         */
        BigInteger n = p.multiply(q);
        BigInteger e = new BigInteger("65537");
        BigInteger phi_n = p.subtract(BigInteger.ONE).multiply(
            q.subtract(BigInteger.ONE));
        BigInteger d = e.modInverse(phi_n);
        System.out.println("Public parameters:");
        System.out.println("n = " + n.toString(16));
        System.out.println("e = " + e.toString(16));
        
        /*
         * The message m is obtained from standard input and is then
         * encoded using the getBytes() String method (UTF-8).
         */
        System.out.print("Enter a message to be signed: ");
        scanner.nextLine();
        String message = scanner.nextLine();
        byte[] mbytes = message.getBytes();
        
        /*
         * If RSA-SHA256 was chosen, the message is hashed using SHA-256. The
         * hash is then used as the encoded "message" for the rest of the
         * algorithm.
         */
        if (hash) {
            MessageDigest h = MessageDigest.getInstance("SHA-256");
            mbytes = h.digest(mbytes);
        }
        BigInteger m = new BigInteger(1, mbytes);
        
        /*
         * If blind signatures are used, the message is masked.
         */
        BigInteger y;
        if (blind) {
            /*
             * Say Alice set up the above instance of RSA signatures. Bob 
             * wants Alice to sign a masked message. He chooses random k that
             * is relatively prime to n.
             * 
             * Since k must be invertible under multiplication mod n, it
             * suffices to choose k to be a random number less than n not
             * equal to p or q. However, Bob does not know the values of p or
             * q, since Alice chose them privately. Therefore, it suffices to
             * check that gcd(k, n) = 1. The chance of gcd(k, n) != 1 is
             * 1 in 2^(2048).
             */
            BigInteger k = new BigInteger(4096, random);
            while (k.compareTo(n) >= 0 || !k.gcd(n).equals(BigInteger.ONE)) {
                k = new BigInteger(4096, random);
            }
            
            /*
             * The mask is t = k^e (mod n). Bob sends z = m * t (mod n) to
             * Alice.
             */
            BigInteger t = k.modPow(e, n);
            BigInteger z = m.multiply(t).mod(n);
            
            /*
             * Alice computes w = z^d (mod n) and send w to Bob. This works
             * because z^d = (m * t)^d 
             *             = (m * k^e)^d 
             *             = m^d * k^(e * d) 
             *             = m^d * k (mod n)
             */
            BigInteger w = z.modPow(d, n);
            
            /*
             * Bob computes y = w * k^(-1) (mod n). This gives 
             * y = z^d * k^(-1) = m^d * k * k^(-1) = m^d (mod n), the valid
             * signature.
             */
            BigInteger kInv = k.modInverse(n);
            y = w.multiply(kInv).mod(n);
        }
        else {
            /*
             * y, the signature, is computed as y = m^d (mod n)
             */
            y = m.modPow(d, n);
        }
        
        /*
         * The signed message is (m, y).
         */
        System.out.println("Signed message:");
        System.out.println("m = " + message);
        System.out.println("y = " + y.toString(16));
        
        /*
         * The following code verifies that the signed message provided is
         * valid.
         * 
         * The receiver of the signed message checks that m = y^e (mod n).
         * 
         * Existential forgeries are possible by choosing any y, computing
         * m = y^e (mod n), and publishing (m, y), which verifies. However,
         * m will probably look like random noise in this case, making
         * existential forgeries largely a non-issue.
         * 
         * In addition, for a signed message (m, y), any signature (z, y), 
         * where message z = m (mod n) would verify as well. However, the
         * probability of z being a meaningful message rather than random 
         * noise is negligible.
         */
        if (m.equals(y.modPow(e, n))) {
            System.out.println("Signature is verified.");
        }
        else {
            // the following line should never be called
            System.out.println("Signature is not verified.");
        }
    }
}
