package crypto;

import java.math.BigInteger;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

/**
 * Elliptic Curve Diffie-Hellman (ECDH) Key Exchange in pure Java.
 * 
 * This implementation of ECDH uses the secp256k1 Koblitz curve, and the public
 * parameters below were taken from page 15 of
 * https://www.secg.org/SEC2-Ver-1.0.pdf
 * 
 * @author Chris Lattman
 */
public class ECDH {
    /*
     * The secp256k1 'a' coefficient.
     */
    private static final String acoef = "0";
    
    /*
     * The secp256k1 'b' coefficient.
     */
    private static final String bcoef = "7";
    
    /*
     * The secp256k1 prime = 2^256 - 2^32 - 2^9 - 2^8 - 2^7 - 2^6 - 2^4 - 1
     */
    private static final String prime = "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"
            + "FFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F";
    
    /*
     * The secp256k1 base point (generator point) x-coordinate. It is the first
     * 32 bytes of the uncompressed form of G, excluding the first byte (used
     * to identify uncompressed points).
     */
    private static final String xcoord = "79BE667EF9DCBBAC55A06295CE870B0"
        + "7029BFCDB2DCE28D959F2815B16F81798";
    
    /*
     * The secp256k1 base point (generator point) y-coordinate. It is the last
     * 32 bytes of the uncompressed form of G.
     */
    private static final String ycoord = "483ADA7726A3C4655DA4FBFC0E1108A"
        + "8FD17B448A68554199C47D08FFB10D4B8";
    
    /*
     * The order of the secp256k1 generator point (cofactor is 1).
     */
    private static final String order = "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFE"
        + "BAAEDCE6AF48A03BBFD25E8CD0364141";

    /**
     * The Elliptic Curve Diffie-Hellman (ECDH) key exchange.
     * 
     * The curve used is secp256k1 using base point g = (x, y)
     *                  
     * y^2 = x^3 + ax + b (mod p)
     *         
     * Public:  (p, curve (a, b), g = (x, y), n, qa, qb)
     * Private: (da, db, s)
     * 
     * @param args not used
     * @throws NoSuchAlgorithmException non-issue
     */
    public static void main(String[] args) throws NoSuchAlgorithmException {
        /*
         * Alice and Bob publicly agree to use the curve (a, b) with prime p
         * and base point (x, y) with order n.
         */
        BigInteger a = new BigInteger(acoef, 16);
        BigInteger b = new BigInteger(bcoef, 16);
        BigInteger p = new BigInteger(prime, 16);
        BigInteger x = new BigInteger(xcoord, 16);
        BigInteger y = new BigInteger(ycoord, 16);
        BigInteger n = new BigInteger(order, 16);
        System.out.println("Public parameters for secp256k1");
        System.out.println("curve: y^2 = x^3 + ax + b (mod p), where:");
        System.out.println("a = " + a.toString(16));
        System.out.println("b = " + b.toString(16));
        System.out.println("p = " + p.toString(16));
        System.out.println("with base point g = (x, y), where:");
        System.out.println("x = " + x.toString(16));
        System.out.println("y = " + y.toString(16));
        System.out.println("and g has order " + n.toString(16));
        
        /*
         * Alice generates da randomly and Bob generates db randomly. These
         * are both private.
         * 
         * The range of da and db is [1, n - 1] (n is 256 bits long)
         * 
         * If da or db are not in the acceptable range, new values of da and
         * db are chosen until they fall in the valid range.
         */
        SecureRandom random = SecureRandom.getInstanceStrong();
        BigInteger da = new BigInteger(n.bitLength(), random);
        BigInteger db = new BigInteger(n.bitLength(), random);
        while (da.compareTo(BigInteger.ONE) < 0 || da.compareTo(n) >= 0 ||
               db.compareTo(BigInteger.ONE) < 0 || db.compareTo(n) >= 0) {
            da = new BigInteger(n.bitLength(), random);
            db = new BigInteger(n.bitLength(), random);
        }
        
        /*
         * Alice's and Bob's public keys qa and qb, respectively, are
         * generated using the Montgomery ladder with base point g and their 
         * private parameters. Their public parameters are both points on the
         * elliptic curve.
         */
        BigInteger[] g = {x, y};
        BigInteger[] qa = montgomeryLadder(g, da, a, b, p);
        BigInteger[] qb = montgomeryLadder(g, db, a, b, p);
        System.out.println("qa = (" + qa[0].toString(16) + ", " + 
            qa[1].toString(16) + ")");
        System.out.println("qb = (" + qb[0].toString(16) + ", " + 
            qb[1].toString(16) + ")");
        
        /*
         * Alice computes point da * qb and Bob computes point db * qa. These
         * should give the same result since 
         * s = da * qb = da * db * G = db * da * G = db * qa
         */
        BigInteger[] secretA = montgomeryLadder(qb, da, a, b, p);
        BigInteger[] secretB = montgomeryLadder(qa, db, a, b, p);
        
        /*
         * This statement ensures the user that s = da * qb = db * qa, hence
         * Alice and Bob have the same secret key.
         */
        if (secretA[0].equals(secretB[0]) && secretA[1].equals(secretB[1])) {
            System.out.println("da * qb == db * qa");
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
     * Special thanks to kelalaka for their explanation:
     * https://crypto.stackexchange.com/a/75879
     * 
     * @param point the curve point to be added to itself
     * @param d the scalar number of times point is added to itself
     * @param a the curve parameter A
     * @param b the curve parameter B
     * @param p the prime field
     * @return the scalar product d * point, a Cartesian coordinate
     */
    private static BigInteger[] montgomeryLadder(BigInteger[] point, 
        BigInteger d, BigInteger a, BigInteger b, BigInteger p) {
        BigInteger[] r0 = {BigInteger.ZERO, BigInteger.ZERO};
        BigInteger[] r1 = point;
        int m = d.bitLength() - 1;
        
        for (int i = m; i >= 0; i--) {
            if (!d.testBit(i)) {
                r1 = pointAdd(r0, r1, a, b, p);
                r0 = pointDouble(r0, a, b, p);
            }
            else {
                r0 = pointAdd(r0, r1, a, b, p);
                r1 = pointDouble(r1, a, b, p);
            }
        }
        
        return r0;
    }
    
    /**
     * The point addition function adds distinct non-identity points.
     * 
     * @param point1 point to be added
     * @param point2 point to be added
     * @param a the curve parameter A
     * @param b the curve parameter B
     * @param p the prime field
     * @return point1 + point2, a Cartesian coordinate
     */
    private static BigInteger[] pointAdd(BigInteger[] point1, 
        BigInteger[] point2, BigInteger a, BigInteger b, BigInteger p) {
        /*
         * The (x, y) coordinates of both points
         */
        BigInteger x1 = point1[0];
        BigInteger y1 = point1[1];
        BigInteger x2 = point2[0];
        BigInteger y2 = point2[1];
        
        /*
         * If the points are identical, return double one of them.
         */
        if (x1.equals(x2) && y1.equals(y2)) {
            return pointDouble(point1, a, b, p);
        }
        
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
         * If the points lie on the same x-axis and are inverses, return the
         * identity.
         */
        if (x1.equals(x2) && y1.add(y2).equals(p)) {
            BigInteger[] identity = {BigInteger.ZERO, BigInteger.ZERO};
            return identity;
        }
        
        /*
         * x3 = alpha^2 - x1 - x2 (mod p) and
         * y3 = alpha * (x1 - x3) - y1 (mod p), where
         * 
         * alpha = (y2 - y1) / (x2 - x1) (mod p)
         */
        BigInteger alpha = y2.subtract(y1).mod(p).multiply(
            (x2.subtract(x1)).modInverse(p));
        
        BigInteger x3 = alpha.pow(2).subtract(x1).subtract(x2).mod(p);
        BigInteger y3 = (alpha.multiply(x1.subtract(x3))).subtract(y1).mod(p);
        
        BigInteger[] sum = {x3, y3};
        return sum;
    }
    
    /**
     * The point double function "doubles" the point using curve arithmetic.
     * 
     * @param point the point to be doubled
     * @param a the curve parameter A
     * @param b the curve parameter B
     * @param p the prime field
     * @return 2 * point, a Cartesian coordinate
     */
    private static BigInteger[] pointDouble(BigInteger[] point, BigInteger a,
        BigInteger b, BigInteger p) {
        /*
         * The (x, y) coordinates of the point
         */
        BigInteger x = point[0];
        BigInteger y = point[1];
        
        /*
         * If the point is the identity, return it.
         */
        if (x.equals(BigInteger.ZERO) && y.equals(BigInteger.ZERO)) {
            return point;
        }
        
        /*
         * x2 = alpha^2 - 2x (mod p) and
         * y2 = alpha * (x - x2) - y (mod p), where
         * 
         * alpha = (3x^2 + a) / (2y) (mod p)
         */
        BigInteger three = new BigInteger("3");
        BigInteger three_xsquared_a = three.multiply(x.pow(2)).add(a);
        BigInteger two_y = BigInteger.TWO.multiply(y);
        BigInteger alpha = three_xsquared_a.mod(p).multiply(
            two_y.modInverse(p));
        
        BigInteger x2 = alpha.pow(2).subtract(x).subtract(x).mod(p);
        BigInteger y2 = (alpha.multiply(x.subtract(x2))).subtract(y).mod(p);
        
        BigInteger[] product = {x2, y2};
        return product;
    }
}
