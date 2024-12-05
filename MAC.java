import java.security.Key;
import java.security.SecureRandom;

import javax.crypto.KeyGenerator;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

public class MAC {
    public static String macString(String input) throws Exception{
        //Hardcoded key
        String key = "S3cr3tK3y1234567";
        SecretKeySpec keySpec = new SecretKeySpec(key.getBytes("UTF-8"), "HmacSHA256");

        //Creating a MAC object
        Mac mac = Mac.getInstance("HmacSHA256");

        //Initializing the Mac object
        mac.init(keySpec);

        //Computing the Mac
        byte[] bytes = input.getBytes("UTF-8");      
        byte[] macResult = mac.doFinal(bytes);

        StringBuilder hexString = new StringBuilder();
        for (byte b : macResult) {
            hexString.append(String.format("%02x", b));
        }

        return hexString.toString();
    }
}
