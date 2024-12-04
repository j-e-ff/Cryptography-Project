import java.security.Key;
import java.security.SecureRandom;

import javax.crypto.KeyGenerator;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

public class MAC {
    public static String macString(String input) throws Exception{
        //Hardcoded key so the macs won't be different with the same message
        String key = "S3cr3tK3y1234567";
        SecretKeySpec keySpec = new SecretKeySpec(key.getBytes(), "HmacSHA256");

        //Creating a MAC object
        Mac mac = Mac.getInstance("HmacSHA256");

        //Initializing the Mac object
        mac.init(keySpec);

        //Computing the Mac
        byte[] bytes = input.getBytes();      
        byte[] macResult = mac.doFinal(bytes);

        StringBuilder hexString = new StringBuilder();
        for (byte b : macResult) {
            hexString.append(String.format("%02x", b));
        }

        return hexString.toString();
    }
}
