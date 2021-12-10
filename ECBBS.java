package crypto;

import java.math.BigInteger;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Scanner;

/**
 * Elliptic Curve Blum-Blum-Shub (ECBBS) pseudorandom number generator in pure
 * Java. This Java program is a modification of
 * https://www.researchgate.net/publication/326276409
 * 
 * Credit goes to authors C. Omorog, B. Gerardo, and R. Medina for inspiring
 * this algorithm.
 * 
 * This implementation of ECBBS uses secp256r1, and the public parameters
 * below were taken from https://www.secg.org/SEC2-Ver-1.0.pdf
 * 
 * @author Chris Lattman
 */
public class ECBBS {
    /*
     * The secp256r1 'a' coefficient.
     */
    private static final String acoef = "FFFFFFFF000000010000000000000000"
        + "00000000FFFFFFFFFFFFFFFFFFFFFFFC";
    
    /*
     * The secp256r1 'b' coefficient.
     */
    private static final String bcoef = "5AC635D8AA3A93E7B3EBBD55769886BC"
        + "651D06B0CC53B0F63BCE3C3E27D2604B";
    
    /*
     * The secp256r1 prime = 2^224 * (2^32 - 1) + 2^192 + 2^96 - 1
     */
    private static final String prime = "FFFFFFFF000000010000000000000000"
        + "00000000FFFFFFFFFFFFFFFFFFFFFFFF";
    
    /*
     * The secp256r1 base point (generator point) x-coordinate.
     */
    private static final String xcoord = "6B17D1F2E12C4247F8BCE6E563A440F"
        + "277037D812DEB33A0F4A13945D898C296";
    
    /*
     * The secp256r1 base point (generator point) y-coordinate.
     */
    private static final String ycoord = "4FE342E2FE1A7F9B8EE7EB4A7C0F9E1"
        + "62BCE33576B315ECECBB6406837BF51F5";
    
    /*
     * The order of the secp256r1 generator point (cofactor is 1).
     */
    private static final String order = "FFFFFFFF00000000FFFFFFFFFFFFFFFF"
        + "BCE6FAADA7179E84F3B9CAC2FC632551";
    
    /**
     * The Elliptic Curve Blum-Blum-Shub (ECBBS) pseudorandom number generator.
     * 
     * @param args not used
     * @throws NoSuchAlgorithmException non-issue
     */
    public static void main(String[] args) throws NoSuchAlgorithmException {
        /*
         * Curve parameters for ECBBS
         */
        BigInteger a = new BigInteger(acoef, 16);
        BigInteger b = new BigInteger(bcoef, 16);
        BigInteger p = new BigInteger(prime, 16);
        BigInteger x = new BigInteger(xcoord, 16);
        BigInteger y = new BigInteger(ycoord, 16);
        BigInteger n = new BigInteger(order, 16);
        
        /*
         * Generate a random d used to calculate random point a_i.
         * 
         * The range of d is [1, n - 1] (n is 256 bits long)
         * 
         * If d is not in the acceptable range, a new value of d is chosen
         * until it falls in the valid range.
         */
        SecureRandom random = SecureRandom.getInstanceStrong();
        BigInteger d = new BigInteger(n.bitLength(), random);
        while (d.compareTo(BigInteger.ONE) < 0 || d.compareTo(n) >= 0) {
            d = new BigInteger(n.bitLength(), random);
        }
        
        /*
         * The random point a_i is generated using the Montgomery ladder.
         */
        BigInteger[] g = {x, y};
        BigInteger[] a_i = montgomeryLadder(g, d, a, b, p);
        
        /*
         * Since floor(log_2(n)) is equal to the bit length of n minus 1, the
         * following code uses the bitLength() function instead.
         * 
         * The range of n_i is [2, floor(log_2(n)) - 1]
         * 
         * If n_i is not in the acceptable range, a new value of n_i is chosen
         * until it falls in the valid range.
         */
        BigInteger n_i_max = BigInteger.valueOf((long) n.bitLength() - 2);
        BigInteger n_i = new BigInteger(n_i_max.bitLength(), random);
        while (n_i.compareTo(BigInteger.TWO) < 0 || 
               n_i.compareTo(n_i_max) >= 0) {
            n_i = new BigInteger(n_i_max.bitLength(), random);
        }
        
        /*
         * Ask user how many random bits are desired.
         */
        Scanner scanner = new Scanner(System.in);
        int bits = 0;
        while (true) {
            try {
                System.out.print("Enter how many random bits ");
                System.out.print("you would like (enter q to quit): ");
                String bitsString = scanner.next();
                if (bitsString.contains("q")) {
                    break;
                }
                bitsString = bitsString.replaceAll("[^0-9]", "");
                bits = Integer.parseInt(bitsString);
                break;
            }
            catch (Exception e) {
                System.out.println("Invalid input.");
            }
        }
        scanner.close();
        
        /*
         * The modified ECBBS algorithm. Instead of using rational numbers,
         * it takes the XOR of the last two bits in each curve point generated.
         * 
         * The output bit is if the XOR is true (equal to 1).
         */
        BigInteger r = BigInteger.ZERO;
        for (int i = 0; i < bits; i++) {
            a_i = montgomeryLadder(a_i, n_i, a, b, p);
            boolean xor = a_i[0].testBit(0) ^ a_i[1].testBit(0);
            if (xor) {
                r = r.setBit(i);
            }
            n_i = n_i.modPow(BigInteger.TWO, n_i_max);
        }
        
        if (bits > 0) {
            System.out.println("Random number (in hex): " + r.toString(16));
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
