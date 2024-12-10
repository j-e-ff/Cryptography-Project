import java.io.File;
import java.io.FileNotFoundException;
import java.util.Base64;
import java.util.Scanner;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.io.FileWriter;
import java.security.*;
import java.nio.file.Files;
import java.nio.file.Paths;

public class Project {
    public static String readFile() {
        // Message from file to be encrypted
        try {
            File myObj = new File("secretMessage.txt");
            Scanner myReader = new Scanner(myObj);
            String data = "";
            while (myReader.hasNextLine()) {
                data += myReader.nextLine() + " ";
            }
            myReader.close();
            return data;
        } catch (FileNotFoundException e) {
            e.printStackTrace();
            return null;
        }
    }

    public static void main(String[] args) {
        Scanner scanner = new Scanner(System.in);
        System.out.println("What will you like to do?:");
        System.out.println("1. Encrypt a message");
        System.out.println("2. Decrypt a message");
        System.out.println("3. Generate KeyPair");
        String userIn = scanner.nextLine();

        switch (userIn) {
            case "1":
                // Hardcode key and salt for simplicity
                String secretKey = "Cryptography";
                String salt = "CS4600";

                // Message to be encrypted
                String originalString = readFile();

                // Encrypt the string
                String encryptedString = AESEncryption.encrypt(originalString, secretKey, salt);

                // Encrypt secretKey and salt using RSA
                String encodedSecretKey = null;
                String encodedSalt = null;

                // getting file name for public key
                System.out.println("Encrypting the secretKey and salt");
                System.out.println("Enter the receiver's public key file name: ");
                String publicKeyFile = scanner.nextLine();
                PublicKey publicKey = null;

                try {
                    publicKey = RSA.loadPublicKey(publicKeyFile);
                } catch (Exception e) {
                    e.printStackTrace();
                }

                byte[] encryptedSecretKey = null;
                byte[] encryptedSalt = null;
                try {
                    encryptedSecretKey = RSA.encrypt(secretKey, publicKey);
                    encryptedSalt = RSA.encrypt(salt, publicKey);

                    // base64 encode to write them as string
                    encodedSecretKey = Base64.getEncoder().encodeToString(encryptedSecretKey);
                    encodedSalt = Base64.getEncoder().encodeToString(encryptedSalt);
                } catch (Exception e) {
                    e.printStackTrace();
                }

                // writing to file
                try {
                    System.out.println("Enter file name for transmitted data (include .txt):");
                    // Write encrypted data and MAC to files
                    Files.write(Paths.get("EncryptedMessage.txt"), encryptedString.getBytes());
                    Files.write(Paths.get("EncryptedKey.txt"), encodedSecretKey.getBytes());
                    Files.write(Paths.get("EncryptedSalt.txt"), encodedSalt.getBytes());
                    try {
                        String msgMac = MAC.macString(encryptedString, secretKey);
                        Files.write(Paths.get("MAC.txt"), msgMac.getBytes());
                    } catch (Exception e) {
                        System.err.println("MAC failed");
                    }

                    System.out.println("Encryption complete. Files generated:");
                    System.out.println("- EncryptedMessage.txt");
                    System.out.println("- EncryptedKey.txt");
                    System.out.println("- EncryptedSalt.txt");
                    System.out.println("- MAC.txt");

                } catch (Exception e) {
                    System.err.println("Failed writing to file");
                }
                break;
            case "2":
                // ask user for the encrypted file name
                System.out.println("Enter the file name containing the encrypted data (include .txt): ");
                String encryptedFileName = scanner.nextLine();

                // Read Encrypted data from the file
                String encryptedMessage = null;
                String Key = null;
                String Salt = null;
                String mac = null;

                try {
                    // Read the encrypted files
                    encryptedMessage = Files.readString(Paths.get("EncryptedMessage.txt")).trim();
                    Key = Files.readString(Paths.get("EncryptedKey.txt")).trim();
                    Salt = Files.readString(Paths.get("EncryptedSalt.txt")).trim();
                    mac = Files.readString(Paths.get("MAC.txt")).trim();
                } catch (Exception e) {
                    System.err.println("File not found: " + encryptedFileName);
                    break;
                }

                // load the RSA private key
                System.out.println("Enter your private key file name: ");
                String privateKeyFile = scanner.nextLine();
                PrivateKey privateKey = null;
                try {
                    privateKey = RSA.loadPrivateKey(privateKeyFile);
                } catch (Exception e) {
                    System.err.println("Failed to load private key");
                }

                // Decrypt the Key and Salt
                try {
                    // convert back to byte from string
                    byte[] encryptedKeyBytes = Base64.getDecoder().decode(Key);
                    byte[] encryptedSaltBytes = Base64.getDecoder().decode(Salt);

                    // Use RSA decryption to decrypt the key and salt
                    Key = RSA.decrypt(encryptedKeyBytes, privateKey);
                    Salt = RSA.decrypt(encryptedSaltBytes, privateKey);
                } catch (Exception e) {
                    System.err.println("Failed to decrypt Key or Salt: " + e.getMessage());
                    break;
                }

                // Decrypt the string
                String decryptedString = AESDecryption.decrypt(encryptedMessage, Key, Salt);
                if (decryptedString != null) {
                    System.out.println("Decrypted String: " + decryptedString + "\n");
                    try {
                        System.out.println("\nMAC Comparison:");
                        String newMac = MAC.macString(encryptedMessage, Key); // Generate MAC for re-encrypted message
                        System.out.println("Original MAC (from file): " + mac);
                        System.out.println("Generated MAC (calculated): " + newMac);
                        if (newMac.equals(mac)) {
                            System.out.println("MACs match");
                        } else {
                            System.out.println("MACs do not match");
                            System.out.println("Original MAC: " + mac);
                            System.out.println("Generated MAC: " + newMac);
                        }
                    } catch (Exception e) {
                        System.err.println("Failed to generate MAC for re-encrypted message");
                    }
                } else {
                    System.err.println("Decryption Failed. :(");
                }
                break;
            case "3":
                // Generating user's keypair
                try {
                    RSA.generateRSAKeyPair();
                } catch (Exception e) {
                    System.err.println("Error generating keys");
                }
                break;
            default:
                System.out.println("Invalid choice");
                break;
        }
    }
}
