import java.security.Key;
import java.security.SecureRandom;

import javax.crypto.KeyGenerator;
import javax.crypto.Mac;

public class MAC {
    public static String macString(String input) throws Exception{
        //Creating KeyGenerator object
        KeyGenerator keyGen = KeyGenerator.getInstance("DES");

        //Creating a SecureRandom object
        SecureRandom secRandom = new SecureRandom();

        //Initializing the KeyGenerator
        keyGen.init(secRandom);

        //Generation a key
        Key key = keyGen.generateKey();

        //Creating a MAC object
        Mac mac = Mac.getInstance("HmacSHA256");

        //Initializing the Mac object
        mac.init(key);

        //Computing the Mac
        String msg = input;
        byte[] bytes = msg.getBytes();      
        byte[] macResult = mac.doFinal(bytes);

        StringBuilder hexString = new StringBuilder();
        for (byte b : macResult) {
            hexString.append(String.format("%02x", b));
        }

        return hexString.toString();
    }
}
