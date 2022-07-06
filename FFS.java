package crypto;

import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
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
        boolean isInteractive = true;
        while (true) {
            System.out.print("Enter 1 for an interactive proof, or enter 2"
                    + " for a non-interactive proof: ");
            int interactive = scanner.nextInt();
            if (interactive != 1 && interactive != 2) {
                System.out.println("Invalid input.");
                continue;
            }
            else if (interactive == 2) {
                isInteractive = false;
            }
            System.out.print("How many secret values would you like to "
                + "generate as the prover? Enter q to quit: ");
            scanner.nextLine();
            kString = scanner.nextLine();
            if (!kString.contains("q")) {
                try {
                    int k = Integer.parseInt(kString.replaceAll("[^0-9]", ""));
                    System.out.println("You have chosen k = " + k);
                    ffs(scanner, k, isInteractive);
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
     * @param scanner standard input from the main function
     * @param k the number of secret values (and public values) to use
     * @param isInteractive whether this proof requires interaction with the 
     * verifier
     * @throws NoSuchAlgorithmException non-issue
     */
    private static void ffs(Scanner scanner, int k, boolean isInteractive) 
            throws NoSuchAlgorithmException {
        /*
         * Two distinct 2048-bit probable primes are chosen. In the rare case
         * that p = q, a new prime q is chosen until they are no longer equal.
         */
        SecureRandom random = SecureRandom.getInstanceStrong();
        BigInteger p = BigInteger.probablePrime(2048, random);
        BigInteger q = BigInteger.probablePrime(2048, random);
        while (p.equals(q)) {
            q = BigInteger.probablePrime(2048, random);
        }
        
        /*
         * n = p * q is computed and the secret values are randomly
         * generated.
         * 
         * Each of the secret values s_i must be relatively prime to n. Since
         * each s_i must be invertible under multiplication mod n, it suffices
         * to choose each s_i to be a random number less than n not equal to p
         * or q.
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
        
        /*
         * If the desired proof is interactive, the prover and verifier
         * exchange information.
         * 
         * If the desired proof is non-interactive, the Fiat-Shamir heuristic
         * is used to simulate interaction between the prover and verifier.
         * 
         * In practice, non-interactive proofs are used. The prover's proof is
         * a tuple of values that a verifier can validate without any
         * interaction with the prover, thus improving efficiency.
         */
        if (isInteractive) {
            System.out.println();
            System.out.print("Would you like to run an instance of the "
                    + "protocol? y/n: ");
            String answer = scanner.nextLine().toLowerCase();
            while (answer.contains("y")) {
                /*
                 * The prover chooses a random number r for each instance. It
                 * must be relatively prime to n. Therefore, it suffices to
                 * choose r to be a random number less than n not equal to p or
                 * q.
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
                        System.out.print("Enter the " + k + "-bit long "
                                + "bitstring (in binary): ");
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
                        System.out.println("Choosing random b...");
                        b = new BigInteger(k, random);
                        while (b.bitLength() != k) {
                            b = new BigInteger(k, random);
                        }
                        break;
                    }
                }
                String format = "b = %0" + k + "d\n";
                System.out.printf(format, Integer.parseInt(b.toString(2)));
                
                /*
                 * The prover computes y = r * s_1^b_1 * ... * s_k^b_k (mod n),
                 * where b_i is the ith bit of b (starting from leftmost bit),
                 * and sends this value to the verifier.
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
        else {
            /*
             * The prover chooses a random number r for each instance. It must
             * be relatively prime to n. Therefore, it suffices to choose r to
             * be a random number less than n not equal to p or q.
             * 
             * The prover calculates x by squaring r (mod n).
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
             * Here, the prover generates b instead of the verifier.
             * 
             * b is chosen to be the last k bits of H(v_1 || ... || v_k || x),
             * where H is a cryptographic hash function. Here, SHA-256 is used.
             */
            MessageDigest h = MessageDigest.getInstance("SHA-256");
            StringBuilder hashBuilder = new StringBuilder();
            for (int i = 0; i < k; i++) {
                hashBuilder.append(values.get(i).toString(2));
            }
            hashBuilder.append(x.toString(2));
            BigInteger concat = new BigInteger(hashBuilder.toString(), 2);
            byte[] hash = h.digest(concat.toByteArray());
            BigInteger modulus = BigInteger.TWO.pow(k);
            BigInteger b = new BigInteger(hash);
            b = b.mod(modulus);
            String format = "b = %0" + k + "d\n";
            System.out.printf(format, Integer.parseInt(b.toString(2)));
            
            /*
             * The prover computes y = r * s_1^b_1 * ... * s_k^b_k (mod n),
             * where b_i is the ith bit of b (starting from leftmost bit).
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
             * The verifier can view the tuple (x, b, y) as well as the public
             * values (v_1,...,v_k) and n at any time, even if the prover is
             * offline.
             * 
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
             * which is how the prover calculated x originally.
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
        }
    }
}
