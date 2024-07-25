import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.net.Socket;
import java.security.PrivateKey;
import java.security.PublicKey;

import javax.crypto.SecretKey;

import org.json.JSONObject;


public class Client{
    protected static final String IDa = "Alice";
    protected static final String IDb = "Bob";
    protected static final String IDc = "Charlie";

    protected String ID;
    protected int nonce;

    protected static PrivateKey PR; 

    public static PublicKey PUk;
    public static PublicKey PUa;
    public static PublicKey PUb;
    public static PublicKey PUc;

    public static SecretKey Ks;

    private Socket socket;
    protected BufferedReader in;
    protected PrintWriter out;
    protected InputHandler inHandler;
    private boolean done;

    public Client(String id) {
        try {
            socket = new Socket(KDC.HOST, KDC.PORT);
            out = new PrintWriter(socket.getOutputStream(), true);
            in = new BufferedReader(new InputStreamReader(socket.getInputStream()));

            System.out.println("\n----------- Established connection with KDC -----------");

            PUk = RSA.getPublicKey(RSA.PUkFILE);
            PUa = RSA.getPublicKey(RSA.PUaFILE);
            PUb = RSA.getPublicKey(RSA.PUbFILE);
            PUc = RSA.getPublicKey(RSA.PUcFILE);

            inHandler = new InputHandler();

            this.ID = id;
            this.nonce = RSA.generateNonce();;

        } catch (Exception e) {
            // TODO: handle exception
        }
    }

    protected void send(JSONObject obj) throws Exception {
        String msg = obj.toString();
        out.println(msg);
        System.out.println("\nMessage sent: " + msg);
        System.out.println(obj.toString(2));
    }

    protected void send(JSONObject obj, PublicKey PU) throws Exception {
        String msg = RSA.encryptOuter(obj.toString(), PU);    
        out.println(msg);
        System.out.println("\nMessage sent: " + msg);
        System.out.println(obj.toString(2));
    }

    private void sendMessage(String msg) throws Exception {
        JSONObject obj = new JSONObject();
        obj.put("M", msg);
        obj.put("ID", ID);
        obj.put("Nk", RSA.generateNonce());
        String objString = obj.toString();
        String cipherText = AES.encrypt(objString, Ks);
        cipherText += ", " + RSA.sign(objString, PR);
        out.println(cipherText);
        System.out.println("\nMessage sent: " + cipherText);
        System.out.println("____________________________________________________________________________\n");
    }

    protected JSONObject receive(String msgKDC) throws Exception {
        System.out.println("\nMessage received: " + msgKDC);

        // Breakdown and print message
        String decryptedMsgKDC = RSA.decryptOuter(msgKDC, PR);
        JSONObject jsonKDC = new JSONObject(decryptedMsgKDC);
        System.out.println(jsonKDC.toString(2));

        return jsonKDC;
    }

    protected JSONObject receiveKey(String msgKDC) throws Exception {
        System.out.println("\nMessage received: " + msgKDC);

        // Breakdown and print message
        String decryptedMsgKDC = RSA.decrypt(msgKDC, PR, PUk);
        JSONObject jsonKDC = new JSONObject(decryptedMsgKDC);
        System.out.println(jsonKDC.toString(2));

        return jsonKDC;
    }

    protected JSONObject receive(String msgKDC, SecretKey K) throws Exception {
        System.out.println("\nMessage received: " + msgKDC);

        // Breakdown and print message
        String decryptedMsgKDC = AES.decrypt(msgKDC, K);
        JSONObject jsonKDC = new JSONObject(decryptedMsgKDC);
        System.out.println(jsonKDC.toString(2));

        return jsonKDC;
    }

    public void shutdown() {
        done = true;
        try {
            in.close();
            out.close();
            if (!socket.isClosed()) {
                socket.close();
            }
        } catch (IOException e) {
            // TODO: handle exception
        }
    }

    protected class InputHandler implements Runnable {

        @Override
        public void run() {
            try {
                BufferedReader reader = new BufferedReader(new InputStreamReader(System.in));
                while (!done) {
                    String input = reader.readLine();
                    if (input.equals("quit")) {
                        reader.close();
                        shutdown();
                    } else {
                        sendMessage(input);
                    }
                }
            } catch (Exception e) {
                // TODO Auto-generated catch block
                e.printStackTrace();
            }
        }
    }
}