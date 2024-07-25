import java.nio.charset.StandardCharsets;
import java.nio.file.Paths;
import java.util.Base64;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import java.io.*;

public class AES {

    private static final String cwd = System.getProperty("user.dir").toString();

    public static final String KaFILE = Paths.get(cwd, "src", "keys", "Ka.dat").toString();
    public static final String KbFILE = Paths.get(cwd, "src", "keys", "Kb.dat").toString();
    public static final String KcFILE = Paths.get(cwd, "src", "keys", "Kc.dat").toString();

    private static final int KEYSIZE = 128;

    public static SecretKey generateAESKey() throws Exception {
        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        keyGenerator.init(KEYSIZE); // You can choose 128, 192, or 256 bits
        return keyGenerator.generateKey();
    }

    private static void generateAESKey(String keyFilePath) throws Exception {
        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        keyGenerator.init(KEYSIZE); // You can choose 128, 192, or 256 bits

        File keyFile = new File(keyFilePath);
        try (FileOutputStream fos = new FileOutputStream(keyFile)) {
            // Write the encoded key to the file
            fos.write(keyGenerator.generateKey().getEncoded());
        }
    }

    public static SecretKey loadKeyFromFile(String keyFilePath) throws Exception {
        File keyFile = new File(keyFilePath);
        try (FileInputStream fis = new FileInputStream(keyFile)) {
            byte[] encodedKey = new byte[(int) keyFile.length()];
            fis.read(encodedKey);

            // Convert the encoded key to a SecretKey object
            return new SecretKeySpec(encodedKey, "AES");
        }
    }

    public static String encrypt(String msg, SecretKey key) throws Exception {
        Cipher cipher = Cipher.getInstance("AES");
        cipher.init(Cipher.ENCRYPT_MODE, key);

        byte[] encryptedBytes = cipher.doFinal(msg.getBytes(StandardCharsets.UTF_8));
        return Base64.getEncoder().encodeToString(encryptedBytes);
    }

    public static String decrypt(String msg, SecretKey key) throws Exception {
        Cipher cipher = Cipher.getInstance("AES");
        cipher.init(Cipher.DECRYPT_MODE, key);

        byte[] encryptedBytes = Base64.getDecoder().decode(msg);
        byte[] decryptedBytes = cipher.doFinal(encryptedBytes);

        return new String(decryptedBytes, StandardCharsets.UTF_8);
    }

    public static void main(String[] args) {
        try {
            // generateAESKey(KaFILE);
            // generateAESKey(KbFILE);
            generateAESKey(KcFILE);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}