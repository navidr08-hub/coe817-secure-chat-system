import java.util.Base64;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import org.json.JSONObject;

public class Charlie extends Client implements Runnable{

    public Charlie(String id) {
        super(id);
        //TODO Auto-generated constructor stub
    }

    private void receiveMessage(String msgKDC) throws Exception {
        String [] message = msgKDC.split(", ");

        // Breakdown and print message
        String decryptedMsg = AES.decrypt(message[0], Ks);
        JSONObject jsonKDC = new JSONObject(decryptedMsg);
        String ID = jsonKDC.getString("ID");
        String M = jsonKDC.getString("M");

        if (ID.equals("Alice")) {
            if (RSA.verify(decryptedMsg, message[1], PUa)) {
                System.out.println("Alice: " + M);
            } else {
                System.out.println("\nMalicious attacker attempted to use fake ID!");
            }
            } else if (ID.equals("Bob")) {
            if (RSA.verify(decryptedMsg, message[1], PUb)) {
                System.out.println("Bob: " + M);
            } else {
                System.out.println("\nMalicious attacker attempted to use fake ID!");
            } 
        }
    }

    @Override
    public void run() {
        try {            
            // Setup and Initialization
            PR = RSA.getPrivateKey(RSA.PRcFILE);
            JSONObject msgC = new JSONObject();
    
            /********************* PHASE 1 - Obtain Master Key ********************/

            // Step 1 - Send IDc
            msgC.put("ID", IDc);
            send(msgC);
    
            // Step 2 - Receive Nk3 and IDk from KDC
            String msgKDC = in.readLine();
            JSONObject jsonKDC = receive(msgKDC);

            int nk3 = jsonKDC.getInt("Nk");
            // String idk = jsonKDC.getString("IDk");

            // Step 3 - Send Nc and Nk3
            msgC = new JSONObject();
            msgC.put("Nc", nonce);
            msgC.put("Nk", nk3);

            send(msgC, PUk);

            // Step 4 - Receive Nk3
            msgKDC = in.readLine();
            jsonKDC = receive(msgKDC);

            nk3 = jsonKDC.getInt("Nk");

            // Step 5 - Receive Kc (Master Key)
            msgKDC = in.readLine();
            jsonKDC = receiveKey(msgKDC);
            // decode the base64 encoded key
            byte[] decodedKey = Base64.getDecoder().decode(jsonKDC.getString("Km"));
            // rebuild key using SecretKeySpec
            SecretKey Kc = new SecretKeySpec(decodedKey, 0, decodedKey.length, "AES");

            /********************* PHASE 2 - Receive Session Key ********************/

            // Step 1 - Receive session key Ks from KDC
            msgKDC = in.readLine();
            jsonKDC = receive(msgKDC, Kc);
            // decode the base64 encoded key
            decodedKey = Base64.getDecoder().decode(jsonKDC.getString("Ks"));
            // rebuild key using SecretKeySpec
            Ks = new SecretKeySpec(decodedKey, 0, decodedKey.length, "AES");

            /********************* PHASE 3 - Secure Chat System ********************/

            Thread t = new Thread(inHandler);

            System.out.println(KDC.s);
            t.start();

            while ((msgKDC = in.readLine()) != null)
                // System.out.println(msgKDC);
                receiveMessage(msgKDC);

        } catch (Exception e) {
            e.printStackTrace();
        } finally {
            System.out.println("\nCharlie: Connection closed with KDC.\n");
        }
    }

    public static void main(String[] args) {
        Charlie charlie = new Charlie(IDc);
        charlie.run();
    }
    
}
