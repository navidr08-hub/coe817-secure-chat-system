import java.util.Base64;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import org.json.JSONObject;

public class Bob extends Client implements Runnable{

    public Bob(String id) {
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
        } else if (ID.equals("Charlie")) {
            if (RSA.verify(decryptedMsg, message[1], PUc)) {
                System.out.println("Charlie: " + M);
            } else {
                System.out.println("\nMalicious attacker attempted to use fake ID!");
            } 
        }
    }

    @Override
    public void run() {
        try {
            // Setup and Initialization
            PR = RSA.getPrivateKey(RSA.PRbFILE);
            JSONObject msgB = new JSONObject();
    
            /********************* PHASE 1 - Obtain Master Key ********************/

            // Step 1 - Send IDb
            msgB.put("ID", IDb);
            send(msgB);
    
            // Step 2 - Receive Nk2 and IDk from KDC
            String msgKDC = in.readLine();
            JSONObject jsonKDC = receive(msgKDC);

            int nk2 = jsonKDC.getInt("Nk");
            // String idk = jsonKDC.getString("IDk");

            // Step 3 - Send Nb and Nk2
            msgB = new JSONObject();
            msgB.put("Nb", nonce);
            msgB.put("Nk", nk2);

            send(msgB, PUk);

            // Step 4 - Receive Nk1
            msgKDC = in.readLine();
            jsonKDC = receive(msgKDC);

            nk2 = jsonKDC.getInt("Nk");

            // Step 5 - Receive Kb (Master Key)
            msgKDC = in.readLine();
            jsonKDC = receiveKey(msgKDC);
            // decode the base64 encoded key
            byte[] decodedKey = Base64.getDecoder().decode(jsonKDC.getString("Km"));
            // rebuild key using SecretKeySpec
            SecretKey Kb = new SecretKeySpec(decodedKey, 0, decodedKey.length, "AES");

            /********************* PHASE 2 - Receive Session Key ********************/

            // Step 1 - Receive session key Ks from KDC
            msgKDC = in.readLine();
            jsonKDC = receive(msgKDC, Kb);
            // decode the base64 encoded key
            decodedKey = Base64.getDecoder().decode(jsonKDC.getString("Ks"));
            // rebuild key using SecretKeySpec
            Ks = new SecretKeySpec(decodedKey, 0, decodedKey.length, "AES");

            /********************* PHASE 3 - Secure Chat System ********************/

            Thread t = new Thread(inHandler);

            System.out.println(KDC.s);
            t.start();

            while ((msgKDC = in.readLine()) != null) {
                // System.out.println(msgKDC);
                receiveMessage(msgKDC);
            }
        
        } catch (Exception e) {
            e.printStackTrace();
        } finally {
            System.out.println("\nBob: Connection closed with KDC.\n");
        }
    }

    public static void main(String[] args) {
        Bob bob = new Bob(IDb);
        bob.run();
    }
    
}
