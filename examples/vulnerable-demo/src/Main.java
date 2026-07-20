import javax.crypto.Cipher;
import java.security.MessageDigest;
public class Main {
    void run() throws Exception {
        Cipher c = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        Cipher des = Cipher.getInstance("DESede/CBC/PKCS5Padding");
        MessageDigest md = MessageDigest.getInstance("SHA-1");
    }
}
