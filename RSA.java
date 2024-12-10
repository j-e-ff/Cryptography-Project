import javax.crypto.Cipher;
import java.io.IOException;
import java.io.FileWriter;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.Base64;
import java.util.Scanner;
import java.security.*;
import java.security.spec.*;

public class RSA {
   public static void generateRSAKeyPair() throws Exception{
        // ask user for file name
        Scanner scan = new Scanner(System.in);
        System.out.print("Enter File Name for Key Pair: ");
        System.out.println("");
        String fileName = scan.nextLine();
       
        
        KeyPairGenerator keyPairGen = KeyPairGenerator.getInstance("RSA");
        keyPairGen.initialize(2048);

        // generating keyPair
        KeyPair kp = keyPairGen.generateKeyPair();
        PublicKey publicKey = kp.getPublic();
        PrivateKey privateKey = kp.getPrivate();

        // writing key pair to files
        try (FileWriter pubWriter = new FileWriter(fileName + "_public.key");
             FileWriter privWriter = new FileWriter(fileName + "_private.key")) {

            pubWriter.write(Base64.getEncoder().encodeToString(publicKey.getEncoded()));
            privWriter.write(Base64.getEncoder().encodeToString(privateKey.getEncoded()));
            pubWriter.close();
            privWriter.close();
        } catch (IOException e) {
            System.out.println("Error writing keys to files: " + e.getMessage());
        }
    }

    public static PublicKey loadPublicKey(String fileName) throws Exception {
        byte[] keyBytes = Base64.getDecoder().decode(Files.readString(Paths.get(fileName)).trim());
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        return keyFactory.generatePublic(new X509EncodedKeySpec(keyBytes));
    }

    public static PrivateKey loadPrivateKey(String fileName) throws Exception {
        byte[] keyBytes = Base64.getDecoder().decode(Files.readString(Paths.get(fileName)).trim());
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        return keyFactory.generatePrivate(new PKCS8EncodedKeySpec(keyBytes));
    }

    public static byte[] encrypt(String message, PublicKey publicKey) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        return cipher.doFinal(message.getBytes());
    }

    public static String decrypt(byte[] cipherText, PrivateKey privateKey) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        return new String(cipher.doFinal(cipherText));
    }
}
