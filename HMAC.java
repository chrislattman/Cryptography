package crypto;

import java.math.BigInteger;
import java.security.MessageDigest;
import java.util.Scanner;

/**
 * HMAC message authentication code in pure Java.
 * 
 * @author Chris Lattman
 */
public class HMAC {
    /*
     * These are the cryptographic hash functions supported by the
     * MessageDigest class.
     */
    public static String[] hashes = {"MD2", "MD5", "SHA-1", "SHA-224", 
        "SHA-256", "SHA-384", "SHA-512/224", "SHA-512/256", "SHA3-224", 
        "SHA3-256", "SHA3-384", "SHA3-512"};
    
    /*
     * The block sizes for the above hash functions, ordered and in bits.
     */
    public static int[] blockSizes = {128, 512, 512, 512, 512, 1024, 1024, 
        1024, 1152, 1088, 832, 576};

    /**
     * The HMAC message authentication code generator. It takes in a hash
     * function name, a message, and a secret key and outputs a hash
     * value corresponding to RFC-2104: https://tools.ietf.org/html/rfc2104
     * 
     * @param args not used
     */
    public static void main(String[] args) {
        /*
         * Asks the user if they want to create a hash.
         */
        Scanner scanner = new Scanner(System.in);
        System.out.print("Do you want to generate a HMAC? y/n: ");
        String answer = scanner.next();
        while (answer.contains("y")) {
            /*
             * Prints out the available hash functions and asks the user
             * which one they want to use. If an invalid function name is
             * given, an exception is thrown and caught.
             */
            System.out.println("The available cryptographic hash functions "
                + "are:");
            System.out.print(hashes[0]);
            for (int i = 1; i < hashes.length; i++) {
                System.out.print(", ");
                System.out.print(hashes[i]);
            }
            System.out.println();
            System.out.print("Enter the hash function you would like: ");
            String function = scanner.next().toUpperCase();
            
            try {
                /*
                 * Prompts the user for the message and the secret key.
                 */
                MessageDigest h = MessageDigest.getInstance(function);
                System.out.print("Enter the message: ");
                scanner.nextLine();
                String message = scanner.nextLine();
                System.out.print("Enter the secret key: ");
                String key = scanner.nextLine();
                
                /*
                 * Messages and keys are encoded using their byte sequences 
                 * as specified by the getBytes() String method. (UTF-8, the
                 * default charset, is used)
                 */
                byte[] mbytes = message.getBytes();
                byte[] kbytes = key.getBytes();
                BigInteger m = new BigInteger(mbytes);
                BigInteger k = new BigInteger(kbytes);
                int kbits = k.toByteArray().length * 8; // 8 bits per byte
                
                /*
                 * At this point, the user has entered a valid hash function
                 * name. The index of the function name is used to obtain the
                 * number of bits, and thus bytes, in the function's block 
                 * size.
                 */
                int index = 0;
                while (index < hashes.length) {
                    if (function.equals(hashes[index])) {
                        break;
                    }
                    index++;
                }
                int blocksizebits = blockSizes[index];
                
                /*
                 * If the key length is greater than the block size of the
                 * chosen hash function, then the key is itself hashed.
                 * 
                 * If the key length is less than the block size of the
                 * chosen hash function, then the key is padded with zeros
                 * to the right by shifting the key to the left. The shift
                 * amount is the difference in bits between the block size
                 * and the key size.
                 */
                if (kbits > blocksizebits) {
                    byte[] oldk = k.toByteArray();
                    byte[] newk = h.digest(oldk);
                    k = new BigInteger(1, newk);
                    kbits = k.bitLength();
                }
                if (kbits < blocksizebits) {
                    int remainder = blocksizebits - kbits;
                    k = k.shiftLeft(remainder);
                }
                
                /*
                 * The inner and outer padding is created below, with the
                 * inner padding consisting of repeated 0x36 bytes and the
                 * outer padding consisting of repeated 0x5C bytes. The
                 * length of both paddings is the block size of the chosen 
                 * hash function.
                 */
                BigInteger opadconst = new BigInteger("5C", 16);
                BigInteger ipadconst = new BigInteger("36", 16);
                BigInteger opad = opadconst;
                BigInteger ipad = ipadconst;
                for (int i = 1; i < blocksizebits / 8; i++) {
                    opad = opad.shiftLeft(8);
                    ipad = ipad.shiftLeft(8);
                    opad = opad.or(opadconst);
                    ipad = ipad.or(ipadconst);
                }
                
                /*
                 * The message m, (possibly hashed) secret key k, inner
                 * padding ipad, and outer padding opad are hashed as 
                 * described below:
                 * 
                 * H((k ^ opad) || H((k ^ ipad) || m))
                 * 
                 * where ^ is XOR and || is concatenation
                 * 
                 * To break down the process, k_opad is the XORed k and opad
                 * chunk whereas k_ipad is the XORed k and ipad chunk.
                 */
                BigInteger k_opad = k.xor(opad);
                BigInteger k_ipad = k.xor(ipad);
                
                /*
                 * k_ipad is shifted left to give room to be ORed, or
                 * concatenated, with message m. If the message's bit length
                 * isn't an even multiple of 4, extra 0s are padded to the 
                 * left. k_ipad is then ORed with m.
                 */
                k_ipad = k_ipad.shiftLeft(m.bitLength());
                if (m.bitLength() % 4 != 0) {
                    k_ipad = k_ipad.shiftLeft(4 - (m.bitLength() % 4));
                }
                k_ipad = k_ipad.or(m);
                
                /*
                 * k_ipad, now concatenated (ORed) with m, is hashed to give
                 * the right "half" of the complete hash. It is then converted
                 * to a BigInteger for the next step.
                 */
                byte[] righthalfhash = h.digest(k_ipad.toByteArray());
                BigInteger righthalf = new BigInteger(1, righthalfhash);
                
                /*
                 * k_opad is shifted left to give room to be ORed, or
                 * concatenated, with righthalf. If righthalf's bit length 
                 * isn't an even multiple of 4, extra 0s are padded to the 
                 * left. k_opad is then ORed with righthalf.
                 */
                k_opad = k_opad.shiftLeft(righthalf.bitLength());
                if (righthalf.bitLength() % 4 != 0) {
                    k_opad = k_opad.shiftLeft(4 - 
                        (righthalf.bitLength() % 4));
                }
                k_opad = k_opad.or(righthalf);
                
                /*
                 * k_opad now represents the complete input to the hash
                 * function. It is hashed, which results in the complete hash.
                 * The hash is converted to a BigInteger and returned.
                 */
                byte[] hash = h.digest(k_opad.toByteArray());
                BigInteger hashvalue = new BigInteger(1, hash);
                System.out.println(hashvalue.toString(16));
            }
            catch (Exception e) {
                System.out.println("Invalid input.");
            }
            System.out.println();
            System.out.print("Do you want to generate a HMAC? y/n: ");
            answer = scanner.next();
        }
        scanner.close();
    }

}
