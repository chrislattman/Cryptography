package crypto;

import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Scanner;

/**
 * Discrete Log Digital Signature Algorithm (DSA) in pure Java. It is based on
 * the ElGamal Signature Scheme.
 * 
 * Whenever setting up a cryptosystem that uses the Discrete Log Problem, use
 * a prime p of the form 4k + 3 that is also a safe prime (p = 2q + 1, q is 
 * also a prime).
 * 
 * @author Chris Lattman
 */
public class DSA {
    /*
     * 2048-bit prime p obtained from https://tools.ietf.org/html/rfc5114
     */
    public static String prime_p = "87A8E61DB4B6663CFFBBD19C651959998CEEF"
        + "608660DD0F25D2CEED4435E3B00E00DF8F1D61957D4FAF7DF4561B2AA3016C"
        + "3D91134096FAA3BF4296D830E9A7C209E0C6497517ABD5A8A9D306BCF67ED9"
        + "1F9E6725B4758C022E0B1EF4275BF7B6C5BFC11D45F9088B941F54EB1E59BB"
        + "8BC39A0BF12307F5C4FDB70C581B23F76B63ACAE1CAA6B7902D52526735488"
        + "A0EF13C6D9A51BFA4AB3AD8347796524D8EF6A167B5A41825D967E144E5140"
        + "564251CCACB83E6B486F6B3CA3F7971506026C0B857F689962856DED4010AB"
        + "D0BE621C3A3960A54E710C375F26375D7014103A4B54330C198AF126116D22"
        + "76E11715F693877FAD7EF09CADB094AE91E1A1597";
    
    /*
     * 256-bit prime q obtained from https://tools.ietf.org/html/rfc5114
     * q is such that q|(p - 1), i.e. q divides p - 1
     */
    public static String prime_q = "8CF83642A709A097B447997640129DA299B1A"
        + "47D1EB3750BA308B0FE64F5FBD3";
    
    /*
     * A generator of p, alpha, from https://tools.ietf.org/html/rfc5114
     * 
     * alpha is such that ord_p(alpha) = q
     */
    public static String generator = "3FB32C9B73134D0B2E77506660EDBD484CA"
        + "7B18F21EF205407F4793A1A0BA12510DBC15077BE463FFF4FED4AAC0BB555B"
        + "E3A6C1B0C6B47B1BC3773BF7E8C6F62901228F8C28CBB18A55AE31341000A6"
        + "50196F931C77A57F2DDF463E5E9EC144B777DE62AAAB8A8628AC376D282D6E"
        + "D3864E67982428EBC831D14348F6F2F9193B5045AF2767164E1DFC967C1FB3"
        + "F2E55A4BD1BFFE83B9C80D052B985D182EA0ADB2A3B7313D3FE14C8484B1E0"
        + "52588B9B7D2BBD2DF016199ECD06E1557CD0915B3353BBB64E0EC377FD0283"
        + "70DF92B52C7891428CDC67EB6184B523D1DB246C32F63078490F00EF8D647D"
        + "148D47954515E2327CFEF98C582664B4C0F6CC41659";

    /**
     * The Digital Signature Algorithm (DSA).
     * 
     * The public parameters p, q, and alpha are given above. DSA uses a 
     * cryptographic hash function to produce a signature. This 
     * implementation of DSA uses SHA3-256.
     * 
     * Public:  (p, q, alpha, beta)
     * Private: (a)
     * 
     * @param args not used
     * @throws NoSuchAlgorithmException non-issue (SHA3-256 is defined)
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
         * a is a private parameter chosen randomly
         * 
         * The range of a is [2, q - 1] and a is in Z*_p, the group of 
         * multiplicative inverses mod p
         * 
         * If a is not in the acceptable range, a new value of a is chosen 
         * until it falls in the valid range.
         */
        SecureRandom random = new SecureRandom();
        BigInteger a = new BigInteger(256, random);
        while (a.compareTo(BigInteger.TWO) < 0 || 
               a.compareTo(q.subtract(BigInteger.ONE)) > 0) {
            a = new BigInteger(256, random);
        }
        
        /*
         * The final public parameter is beta = alpha^a (mod p)
         */
        BigInteger beta = alpha.modPow(a, p);
        System.out.println("beta = " + beta.toString(16));
        
        /*
         * h is an instance of SHA3-256, the cryptographic hash function used 
         * by DSA
         */
        MessageDigest h = MessageDigest.getInstance("SHA3-256");
        
        /*
         * The following loop gives the user the opportunity to sign a
         * message using the created instance of DSA. 
         * 
         * The signed message takes the form (m, r, s), where m is the 
         * message and r and s are signature values.
         */
        Scanner scanner = new Scanner(System.in);
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
            byte[] m = message.getBytes();
            byte[] xbytes = h.digest(m);
            BigInteger x = new BigInteger(xbytes);
            
            /*
             * k is chosen randomly and is in Z*_q, the group of multiplicative 
             * inverses mod q
             * 
             * If k is not in the acceptable range, a new value of k is chosen 
             * until it falls in the valid range.
             * 
             * It is crucial that k is generated randomly with each new 
             * signature. Otherwise DSA is susceptible to attack.
             */
            BigInteger k = new BigInteger(256, random);
            while (k.compareTo(BigInteger.ONE) < 0 || 
                   k.compareTo(q.subtract(BigInteger.ONE)) > 0) {
                k = new BigInteger(256, random);
            }
            
            /*
             * r, the first signature value, is computed as
             * r = (alpha^k (mod p)) (mod q)
             * 
             * s, the last signature value, is computed as
             * s = (x + a * r) * k^(-1) (mod q)
             */
            BigInteger r = alpha.modPow(k, p).mod(q);
            BigInteger ar = a.multiply(r);
            BigInteger kInv = k.modInverse(q);
            BigInteger s = x.add(ar).multiply(kInv).mod(q);
            System.out.println("Signed message:");
            System.out.println("m = " + message);
            System.out.println("r = " + r.toString(16));
            System.out.println("s = " + s.toString(16));
            
            /*
             * The following code verifies that the signature provided is 
             * a valid signature.
             * 
             * The verification process is as follows:
             * 
             * 1. hash the encoded message m (which was done earlier)
             * 2. compute y = (alpha^x * beta^r)^(s^(-1) (mod q)) (mod p)
             * 3. check that y = r (mod q)
             */
            BigInteger power = s.modInverse(q);
            BigInteger base = alpha.modPow(x, p).multiply(beta.modPow(r, p));
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
