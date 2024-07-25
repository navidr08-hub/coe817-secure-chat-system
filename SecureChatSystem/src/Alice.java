import java.util.Base64;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import org.json.JSONObject;

public class Alice extends Client implements Runnable{ 

    public Alice(String id) {
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

        if (ID.equals("Bob")) {
            if (RSA.verify(decryptedMsg, message[1], PUb)) {
                System.out.println("Bob: " + M);
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
            PR = RSA.getPrivateKey(RSA.PRaFILE);
            JSONObject msgA = new JSONObject();
    
            /********************* PHASE 1 - Obtain Master Key ********************/

            // Step 1 - Send IDa
            msgA.put("ID", IDa);
            send(msgA);
    
            // Step 2 - Receive Nk1 and IDk from KDC
            String msgKDC = in.readLine();
            JSONObject jsonKDC = receive(msgKDC);

            int nk1 = jsonKDC.getInt("Nk");
            // String idk = jsonKDC.getString("IDk");

            // Step 3 - Send Na and Nk1
            msgA = new JSONObject();
            msgA.put("Na", this.nonce);
            msgA.put("Nk", nk1);

            send(msgA, PUk);

            // Step 4 - Receive Nk1
            msgKDC = in.readLine();
            jsonKDC = receive(msgKDC);

            nk1 = jsonKDC.getInt("Nk");

            // Step 5 - Receive Ka (Master Key)
            msgKDC = in.readLine();
            jsonKDC = receiveKey(msgKDC);
            // decode the base64 encoded key
            byte[] decodedKey = Base64.getDecoder().decode(jsonKDC.getString("Km"));
            // rebuild key using SecretKeySpec
            SecretKey Ka = new SecretKeySpec(decodedKey, 0, decodedKey.length, "AES");

            /********************* PHASE 2 - Receive Session Key ********************/

            // Step 6 - Send IDa and IDb
            msgA = new JSONObject();
            msgA.put("IDa", IDa);
            msgA.put("IDb", IDb);
            msgA.put("IDc", IDc);
            send(msgA);

            // Step 7 - Receive session key Kab from KDC
            msgKDC = in.readLine();
            jsonKDC = receive(msgKDC, Ka);
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
            System.out.println("\nAlice: Connection closed with KDC.\n");
        }
    }

    public static void main(String[] args) {
        Alice alice = new Alice(IDa);
        alice.run();
    }
    
}
