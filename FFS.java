package crypto;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Scanner;

/**
 * Feige-Fiat-Shamir (FFS) Identification Scheme in pure Java. It is a type of
 * zero-knowledge proof.
 * 
 * @author Chris Lattman
 */
public class FFS {

    /**
     * Entry function for the FFS Identification Scheme.
     * 
     * @param args not used
     */
    public static void main(String[] args) {
        Scanner scanner = new Scanner(System.in);
        String kString = "";
        while (true) {
            System.out.print("How many secret numbers would you like to "
                + "generate as the prover? Enter q to quit: ");
            kString = scanner.nextLine();
            if (!kString.contains("q")) {
                try {
                    int k = Integer.parseInt(kString.replaceAll("[^0-9]", ""));
                    System.out.println("You have chosen k = " + k);
                    ffs(scanner, k);
                    break;
                }
                catch (Exception e) {
                    System.out.println("Invalid input.");
                }
            }
            else {
                break;
            }
        }
        scanner.close();
    }
    
    /**
     * The FFS Identification Scheme.
     * 
     * secrets = (s_1,...,s_k)
     * values = (v_1,...,v_k)
     * 
     * Public: (n, values, x, b, y)
     * Private: (p, q, secrets, r)
     * 
     * @param scanner
     * @param k
     * @return
     */
    public static void ffs(Scanner scanner, int k) {
        /*
         * Two distinct 1024-bit probable primes are chosen. In the rare 
         * case that p = q, a new prime q is chosen until they are no 
         * longer equal.
         */
        SecureRandom random = new SecureRandom();
        BigInteger p = BigInteger.probablePrime(1024, random);
        BigInteger q = BigInteger.probablePrime(1024, random);
        while (p.equals(q)) {
            q = BigInteger.probablePrime(1024, random);
        }
        
        /*
         * n = p * q is computed and the secret numbers are randomly
         * generated.
         * 
         * Each of the secret numbers s_i must be relatively prime to n.
         * Since each s_i must be invertible under multiplication mod n,
         * it suffices to choose each s_i to be a random number less than
         * n not equal to p or q.
         * 
         * Each public value v_i is computed using its corresponding s_i.
         */
        BigInteger n = p.multiply(q);
        BigInteger negativeTwo = BigInteger.TWO.negate();
        ArrayList<BigInteger> secrets = new ArrayList<>();
        ArrayList<BigInteger> values = new ArrayList<>();
        for (int i = 0; i < k; i++) {
            BigInteger s_i = new BigInteger(2048, random);
            while (s_i.compareTo(n) >= 0 || s_i.equals(p) || 
                   s_i.equals(q)) {
                s_i = new BigInteger(2048, random);
            }
            BigInteger v_i = s_i.modPow(negativeTwo, n);
            secrets.add(s_i);
            values.add(v_i);
        }
        System.out.println("Public parameters for duration of the scheme:");
        System.out.println("n = " + n.toString(16));
        for (int i = 0; i < k; i++) {
            System.out.println("v_" + (i + 1) + " = "
                + values.get(i).toString(16));
        }
        
        System.out.println();
        System.out.print("Would you like to run an instance of the protocol? "
            + "y/n: ");
        String answer = scanner.nextLine().toLowerCase();
        while (answer.contains("y")) {
            /*
             * The prover chooses a random number r for each instance. It must
             * be relatively prime to n. Therefore, it suffices to choose r to
             * be a random number less than n not equal to p or q.
             * 
             * The prover calculates x by squaring r (mod n) and sending x
             * to the verifier.
             * 
             * r is a private parameter.
             */
            BigInteger r = new BigInteger(2048, random);
            while (r.compareTo(n) >= 0 || r.equals(p) || r.equals(q)) {
                r = new BigInteger(2048, random);
            }
            BigInteger x = r.modPow(BigInteger.TWO, n);
            System.out.println("x = " + x.toString(16));
            
            /*
             * The verifier generates a random bitstring b that is k bits
             * long and sends it to the prover.
             */
            BigInteger b;
            while (true) {
                System.out.println();
                System.out.print("Would you like to provide your own "
                    + "bitstring as the verifier? y/n: ");
                answer = scanner.nextLine().toLowerCase();
                if (answer.contains("y")) {
                    System.out.print("Enter the " + k + "-bit long bitstring "
                        + "(in binary): ");
                    String bitstring = scanner.nextLine();
                    try {
                        Integer.parseInt(bitstring, 2);
                    }
                    catch (Exception e) {
                        System.out.println("You did not enter a binary "
                            + "bitstring.");
                        continue;
                    }
                    
                    if (bitstring.length() != k) {
                        System.out.println("The bitstring must be " + k + 
                            " bits long.");
                        continue;
                    }
                    b = new BigInteger(bitstring, 2);
                    break;
                }
                else {
                    b = new BigInteger(k, random);
                    while (b.bitLength() != k) {
                        b = new BigInteger(k, random);
                    }
                    break;
                }
            }
            System.out.println("b = " + b.toString(2));
            
            /*
             * The prover computes y = r * s_1^b_1 * ... * s_k^b_k (mod n) and
             * sends this value to the verifier.
             */
            BigInteger y = r;
            for (int i = 0; i < k; i++) {
                boolean b_i = b.testBit(k - i - 1);
                if (b_i) {
                    y = y.multiply(secrets.get(i)).mod(n);
                }
            }
            System.out.println("y = " + y.toString(16));
            
            /*
             * The verifier checks if x = y^2 * v_1^b_1 * ... * v_k^b_k (mod n)
             * This validates the prover because
             * x = y^2 * v_1^b_1 * ... * v_k^b_k (mod n)
             *   = (r * s_1^b_1 * ... * s_k^b_k)^2 * v_1^b_1 * ... * v_k^b_k (mod n)
             *   = r^2 * s_1^(2b_1) * ... * s_k^(2b_k) * v_1^b_1 * ... * v_k^b_k (mod n)
             *   = r^2 * s_1^(2b_1) * ... * s_k^(2b_k) * s_1^(-2b_1) * ... * s_k^(-2b_k) (mod n)
             *   = r^2 * s_1^(2b_1) * s_1^(-2b_1) * ... * s_k^(2b_k) * s_k^(-2b_k) (mod n)
             *   = r^2 * s_1^(2b_1 - 2b_1) * ... * s_k^(2b_k - 2b_k) (mod n)
             *   = r^2 * s_1^0 * ... * s_k^0 (mod n)
             *   = r^2 * 1 * ... * 1 (mod n)
             *   = r^2 (mod n)
             * 
             * which is how the prover calculated x in the first place.
             * 
             * An impersonator of the prover would need to correctly guess the
             * random bitstring b before the verifier sends it. However, the
             * probability of that guess succeeding is 2^(-k).
             */
            BigInteger proof = y.modPow(BigInteger.TWO, n);
            for (int i = 0; i < k; i++) {
                boolean b_i = b.testBit(k - i - 1);
                if (b_i) {
                    proof = proof.multiply(values.get(i)).mod(n);
                }
            }
            if (x.equals(proof)) {
                System.out.println("Prover is verified.");
            }
            else {
                // the following line should never be called
                System.out.println("Prover cannot be verified.");
            }
            
            System.out.println();
            System.out.print("Would you like to run another instance of "
                + "the protocol? y/n: ");
            answer = scanner.nextLine().toLowerCase();
        }
    }
}
