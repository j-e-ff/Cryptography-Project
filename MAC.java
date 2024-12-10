import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

public class MAC {
    public static String macString(String input, String key) throws Exception {
        SecretKeySpec keySpec = new SecretKeySpec(key.getBytes("UTF-8"), "HmacSHA256");
        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(keySpec);

        byte[] macBytes = mac.doFinal(input.getBytes("UTF-8"));
        StringBuilder hexString = new StringBuilder();
        for (byte b : macBytes) {
            hexString.append(String.format("%02x", b));
        }
        return hexString.toString();
    }
}
