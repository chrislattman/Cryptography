package crypto;

import java.math.BigInteger;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Scanner;

public class CoinFlipping {

    /**
     * The remote coin-flipping protocol. Currently broken for large integers.
     * 
     * Public: (n, x)
     * Private: (p, q, a)
     * 
     * @param args not used
     * @throws NoSuchAlgorithmException non-issue
     */
    public static void main(String[] args) throws NoSuchAlgorithmException {
        /*
         * 2048-bit primes p and q are chosen such that they are of the form
         * 4k + 3, which means that the two rightmost (lowest-order) bits
         * should be set to 1.
         */
        SecureRandom random = SecureRandom.getInstanceStrong();
        BigInteger p = BigInteger.probablePrime(2048, random);
        BigInteger q = BigInteger.probablePrime(2048, random);
        while (!p.testBit(0) || !p.testBit(1)) {
            p = BigInteger.probablePrime(2048, random);
        }
        while (p.equals(q) || !q.testBit(0) || !q.testBit(1)) {
            q = BigInteger.probablePrime(2048, random);
        }
        
        /*
         * The guesser computes n = p * q and sends it to the verifier.
         */
        BigInteger n = p.multiply(q);
        System.out.println("n = " + n.toString(16));
        
        /*
         * The verifier chooses a random value a that is relatively prime to n.
         * 
         * The range of a is [1, n - 1]. a is a private parameter.
         * 
         * Assuming the verifier does not know the values of p or q chosen by
         * the guesser, the verifier must choose a such that gcd(a, n) = 1.
         * 
         * n should be large enough such that finding an a where gcd(a, n) != 1
         * is exceedingly rare. Otherwise, the verifier could efficiently
         * factor n, defeating the protocol.
         */
        BigInteger a = new BigInteger(4096, random);
        while (a.compareTo(BigInteger.ONE) < 0 || a.compareTo(n) >= 1 ||
               !a.gcd(n).equals(BigInteger.ONE)) {
            a = new BigInteger(4096, random);
        }
        
        /*
         * The verifier sends x = a^2 (mod n) back to the guesser.
         */
        BigInteger x = a.modPow(BigInteger.TWO, n);
        System.out.println("x = " + x.toString(16));
        
        /*
         * The guesser calculates square roots (guess1, guess2) using the
         * Chinese Remainder Theorem. All roots are reduced modulo n.
         */
        BigInteger[] roots = crt(p, q, x);
        BigInteger guess1 = roots[0];
        BigInteger guess2 = roots[1];
        BigInteger neg_guess1 = guess1.negate().mod(n);
        BigInteger neg_guess2 = guess2.negate().mod(n);
        
        assert guess1.modPow(BigInteger.TWO, n).equals(x);
        assert neg_guess1.modPow(BigInteger.TWO, n).equals(x);
        assert guess2.modPow(BigInteger.TWO, n).equals(x);
        assert neg_guess2.modPow(BigInteger.TWO, n).equals(x);
        assert a.modPow(BigInteger.TWO, n).equals(x);
        assert a.negate().mod(n).modPow(BigInteger.TWO, n).equals(x);
        System.out.println(guess1.mod(n).toString(16));
        System.out.println(neg_guess1.mod(n).toString(16));
        System.out.println(guess2.mod(n).toString(16));
        System.out.println(neg_guess2.mod(n).toString(16));
        System.out.println(a.mod(n).toString(16));
        System.out.println(a.negate().mod(n).toString(16));
        
        /*
         * The guesser chooses one of the pairs (guess1, -guess1) or
         * (guess2, -guess2) and sends it back to the verifier.
         */
        Scanner scanner = new Scanner(System.in);
        int choice;
        while (true) {
            System.out.println("Which pair would you like to guess?");
            System.out.println("1. (" + guess1.toString(16) + ", " + 
                neg_guess1.toString(16) + ")");
            System.out.println("2. (" + guess2.toString(16) + ", " + 
                neg_guess2.toString(16) + ")");
            System.out.print("Enter '1' or '2': ");
            String answer = scanner.next().replaceAll("[^0-9]", "");
            try {
                choice = Integer.parseInt(answer);
                if (choice != 1 && choice != 2) {
                    throw new Exception();
                }
                break;
            }
            catch (Exception e) {
                System.out.println("You did not enter '1' or '2'. Try again.");
            }
        }
        scanner.close();
        
        /*
         * The verifier checks if the guesser chose the right square root.
         */
        if ((choice == 1 && (a.equals(guess1) || a.equals(neg_guess1))) ||
            (choice == 2 && (a.equals(guess2) || a.equals(neg_guess2)))) {
            System.out.println("You chose the correct pair. You win!");
        }
        else {
            System.out.print("You chose the wrong pair. ");
            System.out.println("The correct pair is:");
            System.out.println("(" + a.toString(16) + ", " + 
                    a.negate().mod(n).toString(16) + ")");
        }
    }
    
    /**
     * Chinese Remainder Theorem (CRT) function for two integers.
     * 
     * @param p the prime p
     * @param q the prime q
     * @param x the square of the verifier's choice of a (mod n)
     * @return the square roots of x (mod n)
     */
    private static BigInteger[] crt(BigInteger p, BigInteger q, BigInteger x) {
        BigInteger n = p.multiply(q);
        BigInteger first = x.mod(p).sqrt();
        BigInteger second = x.mod(q).sqrt();
        
        /*
         * Calculate the first square root regularly
         */
        BigInteger w1 = first.multiply(q.modInverse(p)).multiply(q);
        BigInteger w2 = second.multiply(p.modInverse(q)).multiply(p);
        BigInteger guess1 = w1.add(w2).mod(n);
        
        /*
         * Calculate the other square root by negating second.
         */
        second = second.negate().mod(q);
        w2 = second.multiply(p.modInverse(q)).multiply(p);
        BigInteger guess2 = w1.add(w2).mod(n);
        
        BigInteger[] roots = {guess1, guess2};
        return roots;
    }
}
