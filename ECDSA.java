package crypto;

import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Scanner;

/**
 * Elliptic Curve Digital Signature Algorithm (ECDSA) in pure Java.
 * 
 * This implementation of ECDSA uses the secp256k1 Koblitz curve, and the
 * public parameters below were taken from
 * https://www.secg.org/SEC2-Ver-1.0.pdf
 * 
 * @author Chris Lattman
 */
public class ECDSA {
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
     * The Elliptic Curve Digital Signature Algorithm (ECDSA).
     * 
     * The curve used is secp256k1 using base point g = (x, y)
     *                  
     * y^2 = x^3 + ax + b (mod p)
     *                  
     * ECDSA uses a cryptographic hash function to produce a signature. This
     * implementation of ECDSA uses SHA-256.
     *         
     * Public:  (p, curve (a, b), g = (x, y), n, q)
     * Private: (d, k)
     * 
     * @param args not used
     * @throws NoSuchAlgorithmException non-issue (SHA-256 is defined)
     */
    public static void main(String[] args) throws NoSuchAlgorithmException {
        /*
         * The public parameters for this instance of ECDSA.
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
         * d is a private parameter chosen randomly
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
         * The public key q is generated by adding g to itself d times.
         */
        BigInteger[] g = {x, y};
        BigInteger[] q = montgomeryLadder(g, d, a, b, p);
        System.out.println("q = (" + q[0].toString(16) + ", " + 
            q[1].toString(16) + ")");
        
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
            byte[] mbytes = message.getBytes();
            mbytes = h.digest(mbytes);
            BigInteger e = new BigInteger(1, mbytes);
            BigInteger r = BigInteger.ZERO;
            BigInteger s = BigInteger.ZERO;
            
            boolean working = false;
            while (!working) {
                /*
                 * k is chosen randomly and is in the range [1, n - 1]
                 * 
                 * If k is not in the acceptable range, a new value of k is
                 * chosen until it falls in the valid range.
                 * 
                 * It is crucial that k is generated randomly with each new
                 * signature. Otherwise ECDSA is susceptible to attack.
                 */
                BigInteger k = new BigInteger(n.bitLength(), random);
                while (k.compareTo(BigInteger.ONE) < 0 || 
                       k.compareTo(n.subtract(BigInteger.ONE)) > 0) {
                    k = new BigInteger(n.bitLength(), random);
                }
                
                /*
                 * (x1, y1) = k * G
                 */
                BigInteger[] x1y1 = montgomeryLadder(g, k, a, b, p);
                
                /*
                 * r, the first signature value, is computed as r = x1 (mod n)
                 * 
                 * if r = 0, find a new k
                 * 
                 * s, the last signature value, is computed as
                 * s = (e + da * r) * k^(-1) (mod n)
                 * 
                 * if s = 0, find a new k
                 * 
                 * Note that (r, -s (mod n)) is also a valid signature.
                 */
                r = x1y1[0].mod(n);
                if (!r.equals(BigInteger.ZERO)) {
                    working = true;
                }
                
                BigInteger kInv = k.modInverse(n);
                s = (e.add(d.multiply(r))).multiply(kInv).mod(n);
                if (s.equals(BigInteger.ZERO)) {
                    working = false;
                }
            }
            
            System.out.println("Signed message:");
            System.out.println("m = " + e.toString(16) + 
                " (" + message + ")");
            System.out.println("r = " + r.toString(16));
            System.out.println("s = " + s.toString(16));
            
            
            /*
             * The following code verifies that the signed message provided is 
             * valid.
             * 
             * Checking that q is a valid curve point:
             * 
             * 1. check that q is not the identity
             * 2. check that q lies on the curve
             * 3. check that n * q = 0
             * 
             * if any of the above steps are not satisfied, the signature is
             * invalid
             * 
             * The verification process is as follows:
             * 
             * 1. check that r and s are integers in [1, n - 1]
             * 2. hash the encoded message m (which was done earlier)
             * 3. let e be the n.bitLength() leftmost bits in m (done earlier)
             * 4. compute u1 = e * s^(-1) (mod n) and u2 = r * s^(-1) (mod n)
             * 5. check that (x2, y2) = u1 * g + u2 * q =/= 0
             * 6. check that r = x2 (mod n)
             */
            boolean firststeps = true;
            if (q[0].equals(BigInteger.ZERO) && q[1].equals(BigInteger.ZERO)) {
                firststeps = false;
            }
            if (!q[1].modPow(BigInteger.TWO, p).equals(
                q[0].pow(3).add(a.multiply(q[0])).add(b).mod(p))) {
                firststeps = false;
            }
            BigInteger[] nq = montgomeryLadder(q, n, a, b, p);
            if (!nq[0].equals(BigInteger.ZERO) || 
                !nq[1].equals(BigInteger.ZERO)) {
                firststeps = false;
            }
            
            if (firststeps) {
                boolean valid = true;
                if (r.compareTo(BigInteger.ONE) < 0 || r.compareTo(n) >= 0 ||
                    s.compareTo(BigInteger.ONE) < 0 || s.compareTo(n) >= 0) {
                    valid = false;
                }
                BigInteger u1 = e.multiply(s.modInverse(n)).mod(n);
                BigInteger u2 = r.multiply(s.modInverse(n)).mod(n);
                BigInteger[] u1g = montgomeryLadder(g, u1, a, b, p);
                BigInteger[] u2q = montgomeryLadder(q, u2, a, b, p);
                BigInteger[] x2y2 = pointAdd(u1g, u2q, a, b, p);
                if (x2y2[0].equals(BigInteger.ZERO) && 
                    x2y2[1].equals(BigInteger.ZERO)) {
                    valid = false;
                }
                
                if (valid && r.equals(x2y2[0].mod(n))) {
                    System.out.println("Signature is verified.");
                }
                else {
                    // the following line should never be called
                    System.out.println("Signature is not verified.");
                }
            }
            else {
                // the following line should never be called
                System.out.println("Signature is not verified.");
            }
            System.out.println();
            System.out.print("Do you want to sign another message? y/n: ");
            answer = scanner.next().toLowerCase();
        }
        scanner.close();
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
