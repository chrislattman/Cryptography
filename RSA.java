package crypto;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.Scanner;

/**
 * RSA cryptosystem in pure Java.
 * 
 * @author Chris Lattman
 */
public class RSA {

    /**
     * The RSA cryptosystem.
     * 
     * Public:  (n, e)
     * Private: (p, q, d, phi(n))
     * 
     * @param args not used
     */
    public static void main(String[] args) {
        /*
         * Allows the user to use their own primes instead of randomly
         * generated primes. (Sophie Germain prime, safe prime) pairs are used
         * because they are resistant to the Pollard p - 1 algorithm.
         */
        Scanner scanner = new Scanner(System.in);
        System.out.print("Would like you use custom primes, i.e. Sophie "
            + "Germain/safe primes? y/n: ");
        String answer = scanner.next().toLowerCase();
        BigInteger p, q;
        
        if (answer.contains("y")) {
            System.out.println("Enter p and q (in hex):");
            System.out.print("p: ");
            String prime_p = scanner.next();
            System.out.print("q: ");
            String prime_q = scanner.next();
            p = new BigInteger(prime_p, 16);
            q = new BigInteger(prime_q, 16);
        }
        else {
            /*
             * Two distinct 1024-bit probable primes are chosen. In the rare 
             * case that p = q, a new prime q is chosen until they are no 
             * longer equal.
             */
            SecureRandom random = new SecureRandom();
            p = BigInteger.probablePrime(1024, random);
            q = BigInteger.probablePrime(1024, random);
            while (p.equals(q)) {
                q = BigInteger.probablePrime(1024, random);
            }
        }
        
        /*
         * n = p * q is computed and e is set to 65537, a commonly used Fermat
         * prime in RSA. They are both public parameters.
         * 
         * The following private parameters are computed:
         * 
         * phi(n) = phi(p) * phi(q) = (p - 1) * (q - 1)
         * 
         * d = e^(-1) (mod phi(n))
         */
        BigInteger n = p.multiply(q);
        BigInteger e = new BigInteger("65537");
        BigInteger phi_n = p.subtract(BigInteger.ONE).multiply(
            q.subtract(BigInteger.ONE));
        BigInteger d = e.modInverse(phi_n);
        System.out.println("Public parameters:");
        System.out.println("n = " + n.toString(16));
        System.out.println("e = " + e.toString(16));
        
        /*
         * The following loop gives the user the opportunity to use the newly
         * created instance of RSA to encrypt or decrypt messages. 
         * 
         * Messages are encoded using their byte sequences as specified by the
         * getBytes() String method. (UTF-8, the default charset, is used)
         */
        System.out.println();
        System.out.print("Do you want to encrypt or decrypt a message? "
            + "y/n: ");
        answer = scanner.next().toLowerCase();
        while (answer.contains("y")) {
            System.out.print("Encrypt or decrypt? ");
            String direction = scanner.next().toLowerCase();
            if (direction.equals("encrypt")) {
                System.out.print("Enter the plaintext: ");
                scanner.nextLine();
                String plaintext = scanner.nextLine();
                
                /*
                 * To encrypt a plaintext message, encode the message using
                 * getBytes(). Call the encoded message theta. Compute 
                 * gamma = theta^e (mod n).
                 * 
                 * The sender computes this.
                 */
                BigInteger theta = new BigInteger(plaintext.getBytes());
                BigInteger gamma = theta.modPow(e, n);
                System.out.println("Ciphertext: " + gamma.toString(16));
            }
            else if (direction.equals("decrypt")) {
                System.out.print("Enter the ciphertext (in hex): ");
                scanner.nextLine();
                String ciphertext = scanner.nextLine();
                BigInteger gamma = new BigInteger(ciphertext, 16);
                
                /*
                 * To decrypt an encoded ciphertext message (gamma), compute
                 * theta = gamma^d (mod n), then decode theta using the 
                 * toByteArray() BigInteger method to obtain the plaintext 
                 * message.
                 * 
                 * The receiver (owner of the cryptosystem) computes this.
                 */
                BigInteger theta = gamma.modPow(d, n);
                String plaintext = new String(theta.toByteArray());
                System.out.println("Plaintext: " + plaintext);
            }
            else {
                System.out.println("Invalid input.");
            }
            System.out.println();
            System.out.print("Do you want to encrypt or decrypt a "
                + "message? y/n: ");
            answer = scanner.next().toLowerCase();
        }
        scanner.close();
    }
}
