package crypto;

import java.math.BigInteger;
import java.security.SecureRandom;

/**
 * Elliptic Curve Diffie-Hellman (ECDH) Key Exchange in pure Java.
 * 
 * This implementation of ECDH defines point addition and point doubling
 * on a Montgomery curve.
 * 
 * @author Chris Lattman
 */
public class ECDH {
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
     * The Elliptic Curve Diffie-Hellman (ECDH) key exchange.
     * 
     * The curve used is Curve25519, a Montgomery curve which has base point 
     * G = (x, y) = (9, 147816194475895447910205935684099868872646061346164 \
     *                  75288964881837755586237401)
     *         
     * Public:  (p, curve (a, b), G = (x, y), n)
     * Private: (da, db)
     * 
     * @param args not used
     */
    public static void main(String[] args) {
        /*
         * Alice and Bob publicly agree to use the curve (a, b) with prime p 
         * and base point (x, y) with order n.
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
         * Alice generates da randomly and Bob generates db randomly. These
         * are both private.
         * 
         * The range of da and db is [1, n - 1] (n is 253 bits long)
         * 
         * If da or db are not in the acceptable range, new values of da and 
         * db are chosen until they fall in the valid range.
         */
        SecureRandom random = new SecureRandom();
        BigInteger da = new BigInteger(n.bitLength(), random);
        BigInteger db = new BigInteger(n.bitLength(), random);
        while (da.compareTo(BigInteger.ONE) < 0 || 
               da.compareTo(n.subtract(BigInteger.ONE)) > 0 ||
               db.compareTo(BigInteger.ONE) < 0 ||
               db.compareTo(n.subtract(BigInteger.ONE)) > 0) {
            da = new BigInteger(n.bitLength(), random);
            db = new BigInteger(n.bitLength(), random);
        }
        
        /*
         * Alice's and Bob's public parameter qa and qb, respectively, are
         * generated using the Montgomery ladder with base point g and their 
         * private parameters. Their public parameters are both points on the 
         * elliptic curve.
         */
        BigInteger[] g = {x, y};
        BigInteger[] qa = montgomeryLadder(g, da, a, b, n);
        BigInteger[] qb = montgomeryLadder(g, db, a, b, n);
        
        /*
         * Alice computes point da * qb and Bob computes point db * qa. These
         * should give the same result since 
         * da * qb = da * db * G = db * da * G = db * qa
         */
        BigInteger[] secretA = montgomeryLadder(qb, da, a, b, n);
        BigInteger[] secretB = montgomeryLadder(qa, db, a, b, n);
        
        /*
         * This statement ensures the user that da * qb = db * qa, hence 
         * Alice and Bob have the same secret key.
         */
        if (secretA[0].equals(secretB[0]) && secretA[1].equals(secretB[1])) {
            System.out.println("da * qb = db * qa");
        }
        else {
            // the following line should never be called
            System.out.println("da * qb =/= db * qa");
        }
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
         * If the points are negations of each other, return the identity.
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
