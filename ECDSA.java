package crypto;

import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Scanner;

/**
 * Elliptic-Curve Digital Signature Algorithm (ECDSA) in pure Java.
 * 
 * This implementation of ECDSA defines point addition and point doubling
 * on a Montgomery curve.
 * 
 * @author Chris Lattman
 */
public class ECDSA {
    /*
     * The Curve25519 prime = 2^255 - 19
     */
    public static String prime = "7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"
        + "FFFFFFFFFFFFFFFFFFFFFFED";
    
    /*
     * The Curve25519 y-coordinate for base point x = 9
     */
    public static String ycoord = "20AE19A1B8A086B4E01EDD2C7748D14C923D4D7"
        + "E6D7C61B229E9C5A27ECED3D9";
    
    /*
     * The order of the chosen point in the curve
     */
    public static String order = "1000000000000000000000000000000014DEF9DE"
        + "A2F79CD65812631A5CF5D3ED";

    /**
     * The Elliptic Curve Digital Signature Algorithm (ECDSA).
     * 
     * The curve used is Curve25519, a Montgomery curve which has base point 
     * G = (x, y) = (9, 147816194475895447910205935684099868872646061346164 \
     *                  75288964881837755586237401)
     *                  
     * ECDSA uses a cryptographic hash function to produce a signature. This 
     * implementation of ECDSA uses SHA-256.
     *         
     * Public:  (p, curve (a, b), G = (x, y), n)
     * Private: (da, db)
     * 
     * @param args not used
     * @throws NoSuchAlgorithmException non-issue (SHA-256 is defined)
     */
    public static void main(String[] args) throws NoSuchAlgorithmException {
        /*
         * The public parameters for this instance of ECDSA.
         */
        BigInteger a = new BigInteger("486662");
        BigInteger b = BigInteger.ONE;
        BigInteger p = new BigInteger(prime, 16);
        BigInteger x = new BigInteger("9");
        BigInteger y = new BigInteger(ycoord, 16);
        BigInteger n = new BigInteger(order, 16);
        System.out.println("Public parameters:");
        System.out.println("Curve25519 is used");
        System.out.println("curve: By^2 = x^3 + Ax^2 + x, where:");
        System.out.println("A = " + a);
        System.out.println("B = " + b);
        System.out.println("p = " + p);
        System.out.println("with base point G = (x, y), where:");
        System.out.println("x = " + x);
        System.out.println("y = " + y);
        System.out.println("and G has order " + n);
        
        /*
         * da is a private parameter chosen randomly
         * 
         * The range of da is [1, n - 1] (n is 253 bits long)
         * 
         * If da is not in the acceptable range, a new value of a is chosen 
         * until it falls in the valid range.
         */
        SecureRandom random = new SecureRandom();
        BigInteger da = new BigInteger(n.bitLength(), random);
        while (da.compareTo(BigInteger.ONE) < 0 || 
               a.compareTo(n.subtract(BigInteger.ONE)) > 0) {
            a = new BigInteger(n.bitLength(), random);
        }
        
        /*
         * The public key qa is generated by adding G to itself da times.
         */
        BigInteger[] g = {x, y};
        //BigInteger[] qa = montgomeryLadder(g, da, a, b, n);
        
        /*
         * h is an instance of SHA-256, the cryptographic hash function used 
         * by ECDSA
         */
        MessageDigest h = MessageDigest.getInstance("SHA-256");
        
        /*
         * The following loop gives the user the opportunity to sign a
         * message using the created instance of ECDSA. 
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
            byte[] m = message.getBytes();
            byte[] hashbytes = h.digest(m);
            BigInteger e = new BigInteger(1, hashbytes);
            
            /*
             * z is the n.bitLength() (253) leftmost bits of e
             * 
             * 256 - 253 = 3
             */
            BigInteger z = e.shiftRight(3);
            
            /*
             * k is chosen randomly and is in the range [1, n - 1]
             * 
             * If k is not in the acceptable range, a new value of k is chosen 
             * until it falls in the valid range.
             * 
             * It is crucial that k is generated randomly with each new 
             * signature. Otherwise ECDSA is susceptible to attack.
             */
            BigInteger k = new BigInteger(253, random);
            while (k.compareTo(BigInteger.ONE) < 0 || 
                   k.compareTo(n.subtract(BigInteger.ONE)) > 0) {
                k = new BigInteger(253, random);
            }
            
            /*
             * (x1, y1) = k * G
             */
            BigInteger[] x1y1 = montgomeryLadder(g, k, a, b, n);
            
            /*
             * r, the first signature value, is computed as r = x1 (mod n)
             * 
             * if r = 0, find a new k
             * 
             * if s = 0, find a new k
             * 
             * s, the last signature value, is computed as
             * s = (z + da * r) * k^(-1) (mod n)
             */
            BigInteger r = x1y1[0].mod(n);
            BigInteger da_r = da.multiply(r);
            BigInteger z_da_r = z.add(da_r);
            BigInteger kInv = k.modInverse(n);
            BigInteger s = z_da_r.multiply(kInv).mod(n);
            System.out.println("Signed message:");
            System.out.println("m = " + message);
            System.out.println("r = " + r.toString(16));
            System.out.println("s = " + s.toString(16));
            
            /*
             * The following code verifies that the signature provided is 
             * a valid signature.
             * 
             * Checking that qa is a valid curve point:
             * 
             * 1. check that qa is not the identity
             * 2. check that qa lies on the curve
             * 3. check that n * qa = 0
             * 
             * if any of the above steps are not satisfied, the signature is
             * invalid
             * 
             * The verification process is as follows:
             * 
             * 1. check that r and s are integers in [1, n - 1]
             * 2. hash the encoded message m (which was done earlier)
             * 3. let z be the n.bitLength() leftmost bits in e
             * 4. compute u1 = z * s^(-1) (mod n) and u2 = r * s^(-1) (mod n)
             * 5. check that (x2, y2) = u1 * G + u2 * qa =/= 0
             * 6. check that r = x1 (mod n)
             */
            
            System.out.println();
            System.out.print("Do you want to sign a message? y/n: ");
            answer = scanner.next().toLowerCase();
        }
        scanner.close();
    }

    /**
     * The Montgomery ladder implementation. It takes no extra
     * computational time, and provides security against side-channel
     * attacks that use power analysis.
     * 
     * Special thanks to kekalaka for their explanation:
     * https://crypto.stackexchange.com/a/75879
     * 
     * @param point the curve point to be added to itself
     * @param d the scalar number of times point is added to itself
     * @param a the curve parameter A
     * @param b the curve parameter B
     * @param n the order of the field
     * @return the scalar product d * point
     */
    private static BigInteger[] montgomeryLadder(BigInteger[] point, 
        BigInteger d, BigInteger a, BigInteger b, BigInteger n) {
        BigInteger[] r0 = {BigInteger.ZERO, BigInteger.ZERO};
        BigInteger[] r1 = point;
        int m = d.bitLength() - 1;
        
        for (int i = m; i >= 0; i--) {
            if (!d.testBit(i)) {
                r1 = pointAdd(r0, r1, a, b, n);
                r0 = pointDouble(r0, a, b, n);
            }
            else {
                r0 = pointAdd(r0, r1, a, b, n);
                r1 = pointDouble(r1, a, b, n);
            }
        }
        
        return r0;
    }
    
    /**
     * The point addition function assumes that p1 is not equal to p2.
     * 
     * This is specifically for a Montgomery curve.
     * 
     * @param point1 point to be added
     * @param point2 point to be added
     * @param a the curve parameter A
     * @param b the curve parameter B
     * @param n the order of the field
     * @return point1 + point2
     */
    private static BigInteger[] pointAdd(BigInteger[] point1, 
        BigInteger[] point2, BigInteger a, BigInteger b, BigInteger n) {
        /*
         * The (x, y) coordinates of both points
         */
        BigInteger x1 = point1[0];
        BigInteger y1 = point1[1];
        BigInteger x2 = point2[0];
        BigInteger y2 = point2[1];
        
        /*
         * If either of the points is the identity (point at infinity), return
         * the other point.
         */
        if (x1.equals(BigInteger.ZERO) && y1.equals(BigInteger.ZERO)) {
            return point2;
        }
        if (x2.equals(BigInteger.ZERO) && y2.equals(BigInteger.ZERO)) {
            return point1;
        }
        
        /*
         * If the points are equal, return double one of them.
         */
        if (x1.equals(x2) && y1.equals(y2)) {
            return pointDouble(point1, a, b, n);
        }
        
        /*
         * If the points are opposites, return the identity.
         */
        if (x1.equals(x2) && y1.equals(y2.negate())) {
            BigInteger[] identity = {BigInteger.ZERO, BigInteger.ZERO};
            return identity;
        }
        
        BigInteger y2minusy1 = y2.subtract(y1);
        BigInteger x2minusx1 = x2.subtract(x1);
        BigInteger alpha = y2minusy1.divide(x2minusx1);
        
        BigInteger aplusx1plusx2 = a.add(x1).add(x2);
        BigInteger x3 = b.multiply(alpha.pow(2)).subtract(
            aplusx1plusx2);
        BigInteger x1minusx3 = x1.subtract(x3);
        BigInteger y3 = alpha.multiply(x1minusx3).subtract(y1).mod(n);
        
        BigInteger[] sum = {x3.mod(n), y3};
        return sum;
    }
    
    /**
     * The point double function "doubles" the point using curve arithmetic.
     * 
     * This is specifically for a Montgomery curve.
     * 
     * @param point the point to be doubled
     * @param a the curve parameter A
     * @param b the curve parameter B
     * @param n the order of the field
     * @return 2 * point
     */
    private static BigInteger[] pointDouble(BigInteger[] point, BigInteger a, 
        BigInteger b, BigInteger n) {
        /*
         * The (x, y) coordinates of the point
         */
        BigInteger x = point[0];
        BigInteger y = point[1];
        
        /*
         * If the point is the identity (point at infinity), return it.
         */
        if (x.equals(BigInteger.ZERO) && y.equals(BigInteger.ZERO)) {
            return point;
        }
        
        BigInteger three = new BigInteger("3");
        BigInteger three_xsquared = three.multiply(x.pow(2));
        BigInteger two_a_x = BigInteger.TWO.multiply(a).multiply(x);
        BigInteger numerator = three_xsquared.add(two_a_x).add(BigInteger.ONE);
        BigInteger denominator = BigInteger.TWO.multiply(b).multiply(y);
        BigInteger alpha = numerator.divide(denominator);
        
        BigInteger b_alphasquared = b.multiply(alpha.pow(2));
        BigInteger two_x = BigInteger.TWO.multiply(x);
        BigInteger x2 = b_alphasquared.subtract(a).subtract(two_x);
        
        BigInteger xminusx2 = x.subtract(x2);
        BigInteger y2 = alpha.multiply(xminusx2).subtract(y).mod(n);
        
        BigInteger[] product = {x2.mod(n), y2};
        return product;
    }
}
