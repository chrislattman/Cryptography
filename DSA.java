package crypto;

import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Scanner;

/**
 * Discrete Logarithm Digital Signature Algorithm (DSA) in pure Java. It is 
 * based on the ElGamal Signature Scheme.
 * 
 * Whenever setting up a cryptosystem that uses the Discrete Logarithm 
 * Problem, use a prime p of the form 4k + 3 that is also a safe prime 
 * (p = 2q + 1, q is also a prime).
 * 
 * @author Chris Lattman
 */
public class DSA {
    /*
     * 2048-bit prime p obtained from https://tools.ietf.org/html/rfc5114
     */
    private static final String prime_p = "87A8E61DB4B6663CFFBBD19C651959"
        + "998CEEF608660DD0F25D2CEED4435E3B00E00DF8F1D61957D4FAF7DF4561B2"
        + "AA3016C3D91134096FAA3BF4296D830E9A7C209E0C6497517ABD5A8A9D306B"
        + "CF67ED91F9E6725B4758C022E0B1EF4275BF7B6C5BFC11D45F9088B941F54E"
        + "B1E59BB8BC39A0BF12307F5C4FDB70C581B23F76B63ACAE1CAA6B7902D5252"
        + "6735488A0EF13C6D9A51BFA4AB3AD8347796524D8EF6A167B5A41825D967E1"
        + "44E5140564251CCACB83E6B486F6B3CA3F7971506026C0B857F689962856DE"
        + "D4010ABD0BE621C3A3960A54E710C375F26375D7014103A4B54330C198AF12"
        + "6116D2276E11715F693877FAD7EF09CADB094AE91E1A1597";
    
    /*
     * 256-bit prime q obtained from https://tools.ietf.org/html/rfc5114
     * q is such that q|(p - 1), i.e. q divides p - 1
     */
    private static final String prime_q = "8CF83642A709A097B447997640129D"
        + "A299B1A47D1EB3750BA308B0FE64F5FBD3";
    
    /*
     * A generator of p, alpha, from https://tools.ietf.org/html/rfc5114
     * 
     * alpha is such that the multiplicative order of alpha mod p is q
     */
    private static final String generator = "3FB32C9B73134D0B2E77506660ED"
        + "BD484CA7B18F21EF205407F4793A1A0BA12510DBC15077BE463FFF4FED4AAC"
        + "0BB555BE3A6C1B0C6B47B1BC3773BF7E8C6F62901228F8C28CBB18A55AE313"
        + "41000A650196F931C77A57F2DDF463E5E9EC144B777DE62AAAB8A8628AC376"
        + "D282D6ED3864E67982428EBC831D14348F6F2F9193B5045AF2767164E1DFC9"
        + "67C1FB3F2E55A4BD1BFFE83B9C80D052B985D182EA0ADB2A3B7313D3FE14C8"
        + "484B1E052588B9B7D2BBD2DF016199ECD06E1557CD0915B3353BBB64E0EC37"
        + "7FD028370DF92B52C7891428CDC67EB6184B523D1DB246C32F63078490F00E"
        + "F8D647D148D47954515E2327CFEF98C582664B4C0F6CC41659";

    /**
     * The Digital Signature Algorithm (DSA).
     * 
     * The public parameters p, q, and alpha are given above. DSA uses a 
     * cryptographic hash function to produce a signed message. This 
     * implementation of DSA uses SHA-256.
     * 
     * Public:  (p, q, alpha, beta)
     * Private: (a, k)
     * 
     * @param args not used
     * @throws NoSuchAlgorithmException non-issue (SHA-256 is defined)
     */
    public static void main(String[] args) throws NoSuchAlgorithmException {
        /*
         * Primes p and q and generator alpha as shown above. They are public
         * parameters.
         */
        BigInteger p = new BigInteger(prime_p, 16);
        BigInteger q = new BigInteger(prime_q, 16);
        BigInteger alpha = new BigInteger(generator, 16);
        System.out.println("Public parameters:");
        System.out.println("p = " + p.toString(16));
        System.out.println("q = " + q.toString(16));
        System.out.println("alpha = " + alpha.toString(16));
        
        /*
         * a is a private parameter chosen randomly.
         * 
         * The range of a is [2, q - 1].
         * 
         * If a is not in the acceptable range, a new value of a is chosen
         * until it falls in the valid range.
         */
        SecureRandom random = SecureRandom.getInstanceStrong();
        BigInteger a = new BigInteger(256, random);
        if (a.compareTo(BigInteger.TWO) < 0 || a.compareTo(q) >= 0) {
            a = new BigInteger(256, random);
        }
        
        /*
         * The final public parameter is beta = alpha^a (mod p)
         */
        BigInteger beta = alpha.modPow(a, p);
        System.out.println("beta = " + beta.toString(16));
        
        /*
         * h is an instance of SHA-256, the cryptographic hash function used
         * by DSA
         */
        MessageDigest h = MessageDigest.getInstance("SHA-256");
        
        /*
         * The following loop gives the user the opportunity to sign a
         * message using the created instance of DSA. 
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
             * 
             * The hash function is used to create a digest, or hash of the
             * encoded message. The hash itself is a byte array, which is 
             * converted to an integer.
             */
            System.out.print("Enter a message to be signed: ");
            scanner.nextLine();
            String message = scanner.nextLine();
            byte[] mbytes = message.getBytes();
            mbytes = h.digest(mbytes);
            BigInteger m = new BigInteger(1, mbytes);
            
            /*
             * k is a private parameter chosen randomly. 
             * 
             * The range of k is [1, q - 1]. By default, k is relatively prime
             * to q.
             * 
             * If k is not in the acceptable range, a new value of k is chosen
             * until it falls in the valid range.
             * 
             * It is crucial that k is generated randomly with each new
             * signature. Otherwise DSA is susceptible to attack.
             */
            BigInteger k = new BigInteger(256, random);
            while (k.compareTo(BigInteger.ONE) < 0 || k.compareTo(q) >= 0) {
                k = new BigInteger(256, random);
            }
            
            /*
             * r, the first signature value, is computed as
             * r = (alpha^k (mod p)) (mod q)
             * 
             * s, the last signature value, is computed as
             * s = (m + ar) * k^(-1) (mod q)
             */
            BigInteger r = alpha.modPow(k, p).mod(q);
            BigInteger ar = a.multiply(r);
            BigInteger kInv = k.modInverse(q);
            BigInteger s = m.add(ar).multiply(kInv).mod(q);
            System.out.println("Signed message:");
            System.out.println("m = " + m.toString(16) + 
                " (" + message + ")");
            System.out.println("r = " + r.toString(16));
            System.out.println("s = " + s.toString(16));
            
            /*
             * The following code verifies that the signed message provided is
             * valid.
             * 
             * The verification process is as follows:
             * 
             * 1. hash the encoded message m (which was done earlier)
             * 2. compute y = (alpha^m * beta^r)^(s^(-1) (mod q)) (mod p)
             * 3. check that y = r (mod q)
             * 
             * This works because
             * 
             * y = (alpha^m * beta^r)^(s^(-1) (mod q)) (mod p)
             *   = (alpha^m * (alpha^a)^r)^(s^(-1) (mod q)) (mod p)
             *   = (alpha^m * alpha^(ar))^(s^(-1) (mod q)) (mod p)
             *   = (alpha^(m + ar))^(s^(-1) (mod q)) (mod p)
             *   = (alpha^(m + ar))^((m + ar)^(-1) * k (mod q)) (mod p)
             *   = alpha^((m + ar) * (m + ar)^(-1) * k (mod q)) (mod p)
             *   = alpha^k (mod p)
             *   = r (mod q)
             */
            BigInteger power = s.modInverse(q);
            BigInteger base = alpha.modPow(m, p).multiply(beta.modPow(r, p));
            BigInteger y = base.modPow(power, p);
            if (y.mod(q).equals(r)) {
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
