import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.util.Base64;
import java.util.Scanner;

import javax.crypto.Cipher;
import java.io.*;
import java.nio.file.FileAlreadyExistsException;
import java.nio.file.Paths;

import static java.nio.charset.StandardCharsets.UTF_8;


public class RSA {

    private static final String cwd = System.getProperty("user.dir").toString();
    public static final String PRbFILE = Paths.get(cwd, "src", "keys", "PRb.dat").toString();
    public static final String PUbFILE = Paths.get(cwd, "src", "keys", "PUb.dat").toString();
    public static final String PRaFILE = Paths.get(cwd, "src", "keys", "PRa.dat").toString();
    public static final String PUaFILE = Paths.get(cwd, "src", "keys", "PUa.dat").toString();
    public static final String PRcFILE = Paths.get(cwd, "src", "keys", "PRc.dat").toString();
    public static final String PUcFILE = Paths.get(cwd, "src", "keys", "PUc.dat").toString();
    public static final String PRkFILE = Paths.get(cwd, "src", "keys", "PRk.dat").toString();
    public static final String PUkFILE = Paths.get(cwd, "src", "keys", "PUk.dat").toString();

    private static final int KEYSIZE = 2048;

    public static String sign(String message, PrivateKey privateKey) throws Exception {
        Signature signature = Signature.getInstance("SHA256withRSA");
        signature.initSign(privateKey);
        signature.update(message.getBytes());

        // Generate the signature as a byte array
        byte[] signatureBytes = signature.sign();

        // Convert the signature byte array to a Base64-encoded String
        return Base64.getEncoder().encodeToString(signatureBytes);
    }

    public static boolean verify(String msg, String signature, PublicKey publicKey) throws Exception {
        Signature verifier = Signature.getInstance("SHA256withRSA");
        verifier.initVerify(publicKey);
        verifier.update(msg.getBytes());

        // Convert the Base64-encoded signature String to a byte array
        byte[] signatureBytes = Base64.getDecoder().decode(signature);

        // Verify the signature
        return verifier.verify(signatureBytes);
    }

    public static void generateKeyPair(String privateKeyFile, String publicKeyFile) throws Exception {

        try {
            // Generate a new key pair
            KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
            generator.initialize(KEYSIZE, new SecureRandom());
            KeyPair keyPair = generator.generateKeyPair();

            // Save the generated key pair to files
            ObjectOutputStream privateKeyStream = new ObjectOutputStream(new FileOutputStream(privateKeyFile));
            ObjectOutputStream publicKeyStream = new ObjectOutputStream(new FileOutputStream(publicKeyFile));

            privateKeyStream.writeObject(keyPair.getPrivate());
            publicKeyStream.writeObject(keyPair.getPublic());

            privateKeyStream.close();
            publicKeyStream.close();

        } catch (FileAlreadyExistsException faee) {
            System.out.println(privateKeyFile + " " + publicKeyFile + " files already exist.");
        }
    }

    public static PrivateKey getPrivateKey(String privateKeyFile) throws Exception {
        PrivateKey privateKey = null;

        try {
            // Try to load key
            ObjectInputStream privateKeyStream = new ObjectInputStream(new FileInputStream(privateKeyFile));
            privateKey = (PrivateKey) privateKeyStream.readObject();
            privateKeyStream.close();
        } catch (FileNotFoundException fnfe) {
            throw fnfe;
        }

        return privateKey;
    }

    public static PublicKey getPublicKey(String publicKeyFile) throws Exception {
        PublicKey publicKey = null;

        try {
            // Try to load key
            ObjectInputStream publicKeyStream = new ObjectInputStream(new FileInputStream(publicKeyFile));
            publicKey = (PublicKey) publicKeyStream.readObject();
            publicKeyStream.close();
        } catch (FileNotFoundException fnfe) {
            throw fnfe;
        }

        return publicKey;
    }

    public static String encrypt(String msg, PublicKey recipientPublicKey, PrivateKey senderPrivateKey) throws Exception{
        String cipherTextInner = encryptInner(msg, senderPrivateKey);

        final int mid = cipherTextInner.length() / 2; //get the middle of the String
        String[] parts = {cipherTextInner.substring(0, mid), cipherTextInner.substring(mid)};

        //Encrypt the message
        String cipherTextOuter1 = encryptOuter(parts[0], recipientPublicKey);
        String cipherTextOuter2 = encryptOuter(parts[1], recipientPublicKey);

        return cipherTextOuter1 + cipherTextOuter2;
    }

    public static String decrypt(String cipherTextOuter, PrivateKey recipientPrivateKey, PublicKey senderPublicKey) throws Exception {
        final int mid = cipherTextOuter.length() / 2;
        String [] parts = {cipherTextOuter.substring(0, mid), cipherTextOuter.substring(mid)};

        //Decrypt the message
        String cipherTextInner1 = decryptOuter(parts[0], recipientPrivateKey);
        String cipherTextInner2 = decryptOuter(parts[1], recipientPrivateKey);

        return decryptInner(cipherTextInner1 + cipherTextInner2, senderPublicKey);
    }

    public static String encryptOuter(String plainText, PublicKey publicKey) throws Exception {
        Cipher encryptCipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        encryptCipher.init(Cipher.ENCRYPT_MODE, publicKey);

        byte[] cipherText = encryptCipher.doFinal(plainText.getBytes(UTF_8));

        return Base64.getEncoder().encodeToString(cipherText);
    }

    public static String encryptInner(String plainText, PrivateKey privateKey) throws Exception {
        Cipher encryptCipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        encryptCipher.init(Cipher.ENCRYPT_MODE, privateKey);

        byte[] cipherText = encryptCipher.doFinal(plainText.getBytes(UTF_8));

        return Base64.getEncoder().encodeToString(cipherText);
    }

    public static String decryptOuter(String cipherText, PrivateKey privateKey) throws Exception {
        byte[] bytes = Base64.getDecoder().decode(cipherText);
    
        Cipher decriptCipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        decriptCipher.init(Cipher.DECRYPT_MODE, privateKey);
    
        return new String(decriptCipher.doFinal(bytes), UTF_8);
    }

    public static String decryptInner(String cipherText, PublicKey publicKey) throws Exception {
        byte[] bytes = Base64.getDecoder().decode(cipherText);
    
        Cipher decriptCipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        decriptCipher.init(Cipher.DECRYPT_MODE, publicKey);
    
        return new String(decriptCipher.doFinal(bytes), UTF_8);
    }

    public static int generateNonce() {
        return new SecureRandom().nextInt(1000);
    }

    public static void main(String[] args) {
        try {
            Scanner scanner = new Scanner(System.in);
            System.out.print("You> ");
            String input = scanner.nextLine();

            if (input.equals(""))
                System.out.print("Nothing");
            else
                System.out.print("Something");

            scanner.close();
        } catch (Exception e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }
    }
}