package crypto;

import java.math.BigInteger;
import java.security.SecureRandom;

/**
 * Elliptic-Curve Diffie-Hellman (ECDH) Key Exchange in pure Java.
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
     * The Elliptic-Curve Diffie-Hellman (ECDH) key exchange.
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
        BigInteger da = new BigInteger(253, random);
        BigInteger db = new BigInteger(253, random);
        while (da.compareTo(BigInteger.ONE) < 0 || 
               da.compareTo(n.subtract(BigInteger.ONE)) > 0 ||
               db.compareTo(BigInteger.ONE) < 0 ||
               db.compareTo(n.subtract(BigInteger.ONE)) > 0) {
            da = new BigInteger(253, random);
            db = new BigInteger(253, random);
        }
        
        /*
         * Alice's and Bob's public parameter qa and qb, respectively, are
         * generated using the Montgomery ladder with base point g and their 
         * private parameters. Their public parameters are both points on the 
         * elliptic curve.
         */
        Point g = new Point(x, y);
        Point qa = montgomeryLadder(g, da, a, b, n);
        Point qb = montgomeryLadder(g, db, a, b, n);
        
        /*
         * Alice computes point da * qb and Bob computes point db * qa. These
         * should give the same result since 
         * da * qb = da * db * G = db * da * G = db * qa
         */
        Point secretA = montgomeryLadder(qb, da, a, b, n);
        Point secretB = montgomeryLadder(qa, db, a, b, n);
        
        if (secretA.x.equals(secretB.x) && secretA.y.equals(secretB.y)) {
            System.out.println("da * qb = db * qa");
        }
        else {
            // the following line should never be called
            System.out.println("da * qb =/= db * qa");
        }
        System.out.println(da);
        System.out.println(secretA.x);
        System.out.println(secretA.y);
        System.out.println(db);
        System.out.println(secretB.x);
        System.out.println(secretB.y);
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
    private static Point montgomeryLadder(Point point, BigInteger d, 
        BigInteger a, BigInteger b, BigInteger n) {
        Point r0 = new Point(BigInteger.ZERO, BigInteger.ZERO);
        Point r1 = point;
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
    private static Point pointAdd(Point point1, Point point2, BigInteger a, 
        BigInteger b, BigInteger n) {
        /*
         * The (x, y) coordinates of both points
         */
        BigInteger x1 = point1.x;
        BigInteger y1 = point1.y;
        BigInteger x2 = point2.x;
        BigInteger y2 = point2.y;
        
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
        
        if (x1.equals(x2) && y1.equals(y2)) {
            return pointDouble(point1, a, b, n);
        }
        if (x1.equals(x2) && y1.equals(y2.negate())) {
            return new Point(BigInteger.ZERO, BigInteger.ZERO);
        }
        
        BigInteger y2minusy1 = y2.subtract(y1);
        BigInteger x2minusx1 = x2.subtract(x1);
        BigInteger alpha = y2minusy1.divide(x2minusx1);
        
        BigInteger aplusx1plusx2 = a.add(x1).add(x2);
        BigInteger x3 = b.multiply(alpha.pow(2)).subtract(
            aplusx1plusx2);
        BigInteger x1minusx3 = x1.subtract(x3);
        BigInteger y3 = alpha.multiply(x1minusx3).subtract(y1).mod(n);
        
        Point sum = new Point(x3.mod(n), y3);
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
    private static Point pointDouble(Point point, BigInteger a, BigInteger b, 
        BigInteger n) {
        /*
         * The (x, y) coordinates of the point
         */
        BigInteger x = point.x;
        BigInteger y = point.y;
        
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
        
        Point product = new Point(x2.mod(n), y2);
        return product;
    }
    
    /**
     * An inner Point class used to simplify returning coordinates from other
     * functions.
     * 
     * @author Chris Lattman
     */
    private static class Point {
        BigInteger x, y;
        
        Point(BigInteger xcoord, BigInteger ycoord) {
            x = xcoord;
            y = ycoord;
        }
    }
}
