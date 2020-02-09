package crypto;

import java.math.BigInteger;
import java.util.Scanner;

/**
 * SHA3 hash function in pure Java.
 * 
 * @author Chris Lattman
 *
 */
public class SHA3 {

    public static void main(String[] args) {
        Scanner scanner = new Scanner(System.in);
        System.out.print("Enter a message to be hashed: ");
        String message = scanner.nextLine();
        System.out.print("Enter the hash length: ");
        int mdlen = scanner.nextInt();
        scanner.close();
        
        /*
         * This is the byte string of the encoded message
         */
        byte[] encodedMessage = message.getBytes();
        
        /*
         * These are part of the sha3_ctx_t struct
         */
        BigInteger[] b = new BigInteger[200];
        BigInteger[] q = new BigInteger[25];
        
        //-----------------------------------------------------------//
        
        for (int i = 0; i < 25; i++) {
            q[i] = BigInteger.ZERO;
        }
        
        int pt = 0;
        int rsiz = 200 - 2 * mdlen;
        
        //-----------------------------------------------------------//
        
        int j = pt;
        for (int k = 0; k < encodedMessage.length; k++) {
            byte[] currMsgByte = new byte[0];
            currMsgByte[0] = encodedMessage[k];
            BigInteger currByte = new BigInteger(currMsgByte);
            b[j] = b[j].xor(currByte);
            j++;
            if (j >= rsiz) {
                q = sha3_keccakf(q);
                j = 0;
            }
        }
        pt = j;
        
        //-----------------------------------------------------------//
        
        BigInteger first = new BigInteger("6");
        BigInteger last = new BigInteger("128");
        
        b[pt] = b[pt].xor(first);
        b[rsiz - 1] = b[rsiz - 1].xor(last);
        q = sha3_keccakf(q);
        
        // below is unnecessary since it is just an array copy
        /*
        byte[] hash = new byte[mdlen];
        for (int m = 0; m < mdlen; m++) {
            hash[m] = b[m];
        }
        */
        
        //-----------------------------------------------------------//
    }

    public static BigInteger[] sha3_keccakf(BigInteger[] q) {
        BigInteger[] keccakf_rndc = {
            new BigInteger("0000000000000001", 16), 
            new BigInteger("0000000000008082", 16), 
            new BigInteger("800000000000808a", 16),
            new BigInteger("8000000080008000", 16),
            new BigInteger("000000000000808b", 16),
            new BigInteger("0000000080000001", 16),
            new BigInteger("8000000080008081", 16),
            new BigInteger("8000000000008009", 16),
            new BigInteger("000000000000008a", 16), 
            new BigInteger("0000000000000088", 16), 
            new BigInteger("0000000080008009", 16),
            new BigInteger("000000008000000a", 16),
            new BigInteger("000000008000808b", 16),
            new BigInteger("800000000000008b", 16),
            new BigInteger("8000000000008089", 16),
            new BigInteger("8000000000008003", 16),
            new BigInteger("8000000000008002", 16), 
            new BigInteger("8000000000000080", 16), 
            new BigInteger("000000000000800a", 16),
            new BigInteger("800000008000000a", 16),
            new BigInteger("8000000080008081", 16),
            new BigInteger("8000000000008080", 16),
            new BigInteger("0000000080000001", 16),
            new BigInteger("8000000080008008", 16)
        };
        
        BigInteger[] keccakf_rotc = {
            new BigInteger("1"), new BigInteger("3"), new BigInteger("6"),
            new BigInteger("10"), new BigInteger("15"), new BigInteger("21"),
            new BigInteger("28"), new BigInteger("36"), new BigInteger("45"),
            new BigInteger("55"), new BigInteger("2"), new BigInteger("14"),
            new BigInteger("27"), new BigInteger("41"), new BigInteger("56"),
            new BigInteger("8"), new BigInteger("25"), new BigInteger("43"),
            new BigInteger("62"), new BigInteger("18"), new BigInteger("39"),
            new BigInteger("61"), new BigInteger("20"), new BigInteger("44")
        };
        
        BigInteger[] keccakf_piln = {
            new BigInteger("10"), new BigInteger("7"), new BigInteger("11"),
            new BigInteger("17"), new BigInteger("18"), new BigInteger("3"),
            new BigInteger("5"), new BigInteger("16"), new BigInteger("8"),
            new BigInteger("21"), new BigInteger("24"), new BigInteger("4"),
            new BigInteger("15"), new BigInteger("23"), new BigInteger("19"),
            new BigInteger("13"), new BigInteger("12"), new BigInteger("2"),
            new BigInteger("20"), new BigInteger("14"), new BigInteger("22"),
            new BigInteger("9"), new BigInteger("6"), new BigInteger("1")
        };

        BigInteger t;
        BigInteger[] bc = new BigInteger[5];

        for (int r = 0; r < 24; r++) {
            
            for (int i = 0; i < 5; i++) {
                bc[i] = q[i].xor(q[i + 5]).xor(
                    q[i + 10]).xor(q[i + 15]).xor(q[i + 20]);
            }

            for (int i = 0; i < 5; i++) {
                t = bc[(i + 4) % 5].xor(
                    ROTL64(bc[(i + 1) % 5], BigInteger.ONE));
                for (int j = 0; j < 25; j += 5) {
                    q[j + i] = q[j + i].xor(t);
                }
            }

            t = q[1];
            for (int i = 0; i < 24; i++) {
                BigInteger j = keccakf_piln[i];
                bc[0] = q[j.intValueExact()];
                q[j.intValueExact()] = ROTL64(t, keccakf_rotc[i]);
                t = bc[0];
            }

            for (int j = 0; j < 25; j += 5) {
                for (int i = 0; i < 5; i++) {
                    bc[i] = q[j + i];
                }
                
                for (int i = 0; i < 5; i++) {
                    q[j + i] = q[j + i].xor(
                        bc[(i + 1) % 5].not().and(bc[(i + 2) % 5]));
                }
            }

            q[0] = q[0].xor(keccakf_rndc[r]);
        }
        
        return q;
    }
    
    public static BigInteger ROTL64(BigInteger x, BigInteger y) {
        BigInteger sixtyfour = new BigInteger("64");
        return (x.shiftLeft(y.intValueExact()).or(
            x.shiftRight(sixtyfour.subtract(y).intValueExact())));
    }
}
