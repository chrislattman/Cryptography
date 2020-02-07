package crypto;

import java.util.Scanner;

/**
 * Advanced Encryption Standard block cipher in pure Java.
 * 
 * This AES implementation is a command line interface for text-based 
 * plaintexts. The S-box and the powers of x in the AES field are hard-coded.
 * 
 * @author Chris Lattman
 */
public class AES {
    static int[] powers = {1, 2, 4, 8, 16, 32, 64, 128, 27, 64};
    static int[] Sbox = {0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 
        0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76,
        0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 
        0x9C, 0xA4, 0x72, 0xC0,
        0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 
        0x71, 0xD8, 0x31, 0x15,
        0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 
        0xEB, 0x27, 0xB2, 0x75,
        0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 
        0x29, 0xE3, 0x2F, 0x84,
        0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 
        0x4A, 0x4C, 0x58, 0xCF,
        0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 
        0x50, 0x3C, 0x9F, 0xA8,
        0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 
        0x10, 0xFF, 0xF3, 0xD2,
        0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 
        0x64, 0x5D, 0x19, 0x73,
        0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 
        0xDE, 0x5E, 0x0B, 0xDB,
        0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 
        0x91, 0x95, 0xE4, 0x79,
        0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 
        0x65, 0x7A, 0xAE, 0x08,
        0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 
        0x4B, 0xBD, 0x8B, 0x8A,
        0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 
        0x86, 0xC1, 0x1D, 0x9E,
        0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 
        0xCE, 0x55, 0x28, 0xDF,
        0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 
        0xB0, 0x54, 0xBB, 0x16};

    /**
     * Handles I/O for AES.
     * 
     * @param args not used
     */
    public static void main(String[] args) {
        Scanner scanner = new Scanner(System.in);
        System.out.println("This is the AES algorithm.");
        
        String direction = "";
        while (!direction.toLowerCase().equals("encrypt") && 
               !direction.toLowerCase().equals("decrypt")) {
            System.out.print("Enter encrypt or decrypt: ");
            direction = scanner.next();
            System.out.println();
        }
        
        String mode = "";
        while (!mode.toUpperCase().equals("ECB") && 
               !mode.toUpperCase().equals("CBC")) {
            System.out.print("Enter the mode (ECB or CBC): ");
            mode = scanner.next();
            System.out.println();
        }
        
        int bits = 0;
        while (bits != 128 && bits != 192 && bits != 256) {
            System.out.print("Enter 128, 192, or 256 for bits: ");
            bits = scanner.nextInt();
            System.out.println();
        }
        
        String key = "";
        int numkeybits = key.getBytes().length * 4; // multiplied by 4 since
        while (numkeybits != bits) {                // string digits are bytes
            System.out.print("Enter a " + bits + "-bit key: ");
            key = scanner.next();
            while (key.length() < 32) {
                key = "0" + key;
            }
            numkeybits = key.getBytes().length * 4;
            System.out.println();
        }
        
        if (direction.equals("encrypt")) {
            System.out.print("Enter the plaintext: ");
            scanner.nextLine();
            String plaintext = scanner.nextLine();
            System.out.println();
            System.out.print("ciphertext: ");
            aes(plaintext, key, bits, mode); //print this out
        }
        else {
            System.out.print("Enter the ciphertext: ");
            //String ciphertext = scanner.nextLine();
            System.out.println();
            System.out.print("plaintext: ");
            //decrypt(ciphertext, key, bits, mode);
        }
        
        scanner.close();
    }

    /**
     * The main AES function used to encrypt plaintext with a key.
     * 
     * @param plaintext the text to be encrypted
     * @param key the secret key
     * @param bits either 128, 192, or 256
     * @param mode electronic codebook or cipher block chaining mode
     * @return the AES state matrix (stored as an array)
     */
    public static byte[] aes(String plaintext, String key, int bits, 
        String mode) {
        byte[] plain = plaintext.getBytes();
        byte[] state = new byte[bits / 8];
        System.arraycopy(plain, 0, state, 0, plain.length);
        byte[] roundKey = makeRoundKey(key);
        
        state = addRoundKey(state, roundKey, 0);
        int moreRounds = (bits - 128) / 32;
        for (int i = 1; i <= 10 + moreRounds; i++) {
            state = byteSub(state);
            state = shiftRow(state);
            if (i < 10) {
                state = mixCol(state);
            }
            state = addRoundKey(state, roundKey, (4 + moreRounds) * i);
        }
        
        return state;
    }
    
    /**
     * Makes the 4x44 round key matrix (stored as an array).
     * 
     * @param key the secret key
     * @return the round key matrix
     */
    public static byte[] makeRoundKey(String key) {
        byte[] keybytes = key.getBytes();
        byte[] roundKey = new byte[4 * 44];
        System.arraycopy(keybytes, 0, roundKey, 0, keybytes.length);
        int columns = keybytes.length / 4;
        
        for (int i = 4 * columns; i <= 43 * columns; i += columns) {
            if (i / columns % 4 != 0) {
                roundKey[i] = (byte) (roundKey[i - 4] ^ roundKey[i - 16]);
                roundKey[i + 1] = (byte) (roundKey[i - 3] ^ roundKey[i - 15]);
                roundKey[i + 2] = (byte) (roundKey[i - 2] ^ roundKey[i - 14]);
                roundKey[i + 3] = (byte) (roundKey[i - 1] ^ roundKey[i - 13]);
            }
            else {
                roundKey[i] = (byte) (roundKey[i - 16] ^ 
                    (Sbox[roundKey[i - 3]] ^ powers[((i / columns) - 4) / 4]));
                roundKey[i + 1] = (byte) (roundKey[i - 15] ^ 
                    Sbox[roundKey[i - 2]]);
                roundKey[i + 2] = (byte) (roundKey[i - 14] ^ 
                    Sbox[roundKey[i - 1]]);
                roundKey[i + 2] = (byte) (roundKey[i - 13] ^ 
                    Sbox[roundKey[i - 4]]);
            }
        }
        
        return roundKey;
    }
    
    /**
     * XORs the round key matrix starting at column startColumn to the 
     * state matrix.
     * 
     * @param state the AES state matrix
     * @param roundKey the round key matrix
     * @param startColumn the column to start copying from
     * @return the matrix sum
     */
    public static byte[] addRoundKey(byte[] state, byte[] roundKey, 
        int startColumn) {
        
        for (int i = 0; i < state.length; i++) {
            state[i] ^= roundKey[startColumn * 4 + i];
        }
        
        return state;
    }
    
    /**
     * Replaces each byte b in the state matrix with its S-box output, S(b).
     * 
     * @param state the AES state matrix
     * @return the state matrix with bytes substituted for S-box outputs
     */
    public static byte[] byteSub(byte[] state) {
        
        for (int i = 0; i < state.length; i++) {
            state[i] = (byte) Sbox[state[i]];
        }
        
        return state;
    }
    
    /**
     * Performs a cyclical left-shift for each row in the state matrix. The 
     * shift is done n times for each row n, starting at row 0.
     *  
     * @param state
     * @return
     */
    public static byte[] shiftRow(byte[] state) {
        return null;
    }
    
    /**
     * Replaces the state matrix with M x A, where M is the matrix
     * [02, 03, 01, 01; 01, 02, 03, 01; 01, 01, 02, 03; 03, 01, 01, 02]
     * 
     * @param state the AES state matrix
     * @return the matrix product
     */
    public static byte[] mixCol(byte[] state) {
        return null;
    }
}
