import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.ArrayList;
import java.util.Base64;
import java.util.concurrent.CyclicBarrier;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import org.json.JSONObject;

public class KDC implements Runnable{
    // Socket variables 
    private ServerSocket server;
    public static final String HOST = "localhost";
    public static final int PORT = 15000;
    private boolean done;

    // Thread variables
    public static CyclicBarrier p1 = new CyclicBarrier(3);
    public static CyclicBarrier p2 = new CyclicBarrier(3);
    public static CyclicBarrier p3 = new CyclicBarrier(3);

    private ArrayList<ConnectionHandler> connections;
    private ExecutorService pool;

    // Encryption variables

    public static final String IDk = "KDC";

    protected static PrivateKey PRk;
    protected static PublicKey PUa;
    protected static PublicKey PUb;
    protected static PublicKey PUc;

    protected static SecretKey Ka;
    protected static SecretKey Kb;
    protected static SecretKey Kc;

    protected static int Nk1;
    protected static int Nk2;
    protected static int Nk3;

    private static volatile String Ks;

    public static final String s = "\n********************************************************************************************************\n" 
                                     + "                                         Entering Secure Chat                                           \n"
                                     + "********************************************************************************************************";

    public KDC() {
        try {
            // Setup and Initialization
            connections = new ArrayList<>();

            PRk = RSA.getPrivateKey(RSA.PRkFILE);

            PUa = RSA.getPublicKey(RSA.PUaFILE);
            PUb = RSA.getPublicKey(RSA.PUbFILE);
            PUc = RSA.getPublicKey(RSA.PUcFILE);

            Ka = AES.loadKeyFromFile(AES.KaFILE);
            Kb = AES.loadKeyFromFile(AES.KbFILE);
            Kc = AES.loadKeyFromFile(AES.KcFILE);

            Nk1 = RSA.generateNonce();
            Nk2 = RSA.generateNonce();
            Nk3 = RSA.generateNonce();
            
            done = false;
        } catch (Exception e) {
            // TODO: handle exception
        }
    }

    public void shutdown() {
        try {
            done = true;
            if (!server.isClosed()) {
                server.close();
            }
            for (ConnectionHandler ch : connections) {
                ch.shutdown();
            }
        } catch (IOException e) {
            // TODO: handle exception
        }
    }

    @Override
    public void run() {
        try {
            this.server = new ServerSocket(PORT);
            System.out.println("\nKDC listening on PORT " + PORT + " ...");

            this.pool = Executors.newCachedThreadPool();
    
            while (this.connections.size() < 3 && !done) {
                Socket client = server.accept();
                ConnectionHandler handler = new ConnectionHandler(client);
                this.connections.add(handler);
                this.pool.execute(handler);
            }

        } catch (Exception e) {
            e.printStackTrace();
            shutdown();
        }   
    }

    public static void main(String[] args) {
        KDC kdc = new KDC();
        kdc.run();
    }

    class ConnectionHandler implements Runnable {
    
        // Socket variables
        private Socket client;
        private BufferedReader in;
        private PrintWriter out;

        // Helper variables
        private String msgClient;
        private JSONObject jsonClient;
        private JSONObject msgKDC = new JSONObject();
        private String ID;

        public ConnectionHandler(Socket client) throws Exception{
            this.client = client;
        }

        @Override
        public void run() {
            try {
                this.in = new BufferedReader(new InputStreamReader(this.client.getInputStream()));
                this.out = new PrintWriter(this.client.getOutputStream(), true);

                System.out.println("\n----------- New connection -----------\n");
                System.out.println("Client connected: " + client.getInetAddress());

                while ((msgClient = in.readLine()) != null) {

                    /********************* PHASE 1 - Distribute Master Key ********************/

                    // Step 1 - Recieve ID from client
                    jsonClient = receive(msgClient);
                    ID = jsonClient.getString("ID");

                    if (ID.equals("Alice")){
                        // Wait for 3 clients to connect
                        p1.await();
                        phase1(PUa, Nk1, Ka);

                        /********************* PHASE 2 - Distribute Session Key ********************/

                        // Step 1 - Receive IDa and IDb
                        msgClient = in.readLine();
                        jsonClient = receive(msgClient);

                        if (jsonClient.has("IDa") && jsonClient.has("IDb") && jsonClient.has("IDc")){
                            // Step 2 - Send Ks to Alice
                            msgKDC = new JSONObject();
                            Ks = Base64.getEncoder().encodeToString(AES.generateAESKey().getEncoded());
                            msgKDC.put("Ks", KDC.Ks);
                            send(msgKDC, Ka);

                            p2.await();

                        } else {
                            throw new Exception("IDa, IDb and IDc not found in msg at Step 1 of Phase 2.");
                        }

                        p3.await();
                        System.out.println(s);

                    } else if (ID.equals("Bob")){
                        // Wait for 2 clients to connect
                        p1.await();
                        phase1(PUb, Nk2, Kb);

                        p2.await();
                        phase2(Kb);

                        p3.await();
                    } else if (ID.equals("Charlie")){
                        // Wait for 3 clients to connect
                        p1.await();
                        phase1(PUc, Nk3, Kc);

                        p2.await();
                        phase2(Kc);

                        p3.await();
                    } else {
                        throw new Exception("ID of client does not match any registered client IDs");
                    }

                    break;
                }

                /********************* PHASE 3 - Secure Chat System ********************/
                
                byte [] decodedKey = Base64.getDecoder().decode(Ks);
                SecretKey sessionKey = new SecretKeySpec(decodedKey, 0, decodedKey.length, "AES");

                Nk1 = 0; Nk2 = 0; Nk3 = 0;

                while ((msgClient = in.readLine()) != null) {
                    phase3(msgClient, sessionKey);
                }

            } catch (Exception e) {
                e.printStackTrace();
                shutdown();
            }
        }

        public void forward(String msg) throws Exception {
            for (ConnectionHandler ch : connections){
                if (ch != null && ch != this) {
                    ch.send(msg);
                }
            }
        }

        private void send(String msg) throws Exception {
            out.println(msg);
        }

        private void send(JSONObject obj, SecretKey key) throws Exception {
            String msg = AES.encrypt(obj.toString(), key);
            out.println(msg);
            System.out.println("\nMessage sent: " + msg);
            System.out.println(obj.toString(2));
        }

        private void send(JSONObject obj, PublicKey publicKey) throws Exception {
            String msg = RSA.encryptOuter(obj.toString(), publicKey);
            out.println(msg);
            System.out.println("\nMessage sent: " + msg);
            System.out.println(obj.toString(2));
        }

        private void sendKey(JSONObject obj, PublicKey PU) throws Exception {
            String msg = RSA.encrypt(obj.toString(), PU, PRk);
            out.println(msg);
            System.out.println("\nMessage sent: " + msg);
            System.out.println(obj.toString(2));
        }

        private JSONObject receive(String msgClient) throws Exception {
            System.out.println("Message received: " + msgClient);

            // Step 1 - Recieve ID from client
            JSONObject jsonClient = new JSONObject(msgClient);
            System.out.println(jsonClient.toString(2));

            return jsonClient;
        }

        private JSONObject receive(String msgClient, PrivateKey PRk) throws Exception {
            System.out.println("\nMessage received: " + msgClient);
            String decryptedMsgClient = RSA.decryptOuter(msgClient, PRk);

            JSONObject jsonClient = new JSONObject(decryptedMsgClient);
            System.out.println(jsonClient.toString(2));

            return jsonClient;
        }

        private String [] receiveMessage(String msgKDC, SecretKey Ks) throws Exception {
            System.out.println("\nMessage received: " + msgKDC);

            String [] message = msgKDC.split(", ");
            message[0] = AES.decrypt(message[0], Ks);

            return message;
        }

        private void phase1(PublicKey PU, int Nk, SecretKey K) throws Exception {
            // Step 2 - Send Nk1 and IDk to client
            msgKDC.put("Nk", Nk);
            msgKDC.put("IDk", IDk);

            send(msgKDC, PU);

            // Step 3 - Receive Na and Nk1
            msgClient = in.readLine();
            jsonClient = receive(msgClient, PRk);

            // Step 4 - Send Nk1
            msgKDC = new JSONObject();
            msgKDC.put("Nk", Nk);

            send(msgKDC, PU);

            // Step 5 - Send ecnrypted master key with PRk
            msgKDC = new JSONObject();
            // get base64 encoded version of the key
            String encodedKey = Base64.getEncoder().encodeToString(K.getEncoded());
            msgKDC.put("Km", encodedKey);

            sendKey(msgKDC, PU);
        }

        private void phase2(SecretKey K) throws Exception {
            msgKDC = new JSONObject();
            msgKDC.put("Ks", KDC.Ks);
            send(msgKDC, K);
        }

        public void phase3(String msgClient, SecretKey sessionKey) throws Exception {
            // Receive the client's message
            String message [] = receiveMessage(msgClient, sessionKey);
            jsonClient = new JSONObject(message[0]);

            if (ID.equals("Alice")) {
                int nonce = jsonClient.getInt("Nk");
                if (nonce == Nk1){
                    throw new Exception("Nk1 matches previous nonce. Replay attack!");
                } else {
                    Nk1 = nonce;
                    // verify the client's signature
                    if (RSA.verify(message[0], message[1], PUa)){
                        // Forward the message to the other clients
                        forward(msgClient);
                    } else {
                        throw new Exception("Malicious attacker attempted to use fake ID!");
                    }
                }
            } else if (ID.equals("Bob")) {
                int nonce = jsonClient.getInt("Nk");
                if (nonce == Nk2){
                    throw new Exception("Nk2 matches previous nonce. Replay attack!");
                } else {
                    Nk2 = nonce;
                    // verify the client's signature                        
                    if (RSA.verify(message[0], message[1], PUb)){
                        // Forward the message to the other clients
                        // forward(msgClient);
                        forward(msgClient);
                    } else {
                        throw new Exception("Malicious attacker attempted to use fake ID!");
                    }
                }
            } else if (ID.equals("Charlie")) {
                int nonce = jsonClient.getInt("Nk");
                if (nonce == Nk3){
                    throw new Exception("Nk3 matches previous nonce. Replay attack!");
                } else {
                    Nk3 = nonce;
                    // verify the client's signature                        
                    if (RSA.verify(message[0], message[1], PUc)){
                        // Forward the message to the other clients
                        forward(msgClient);
                    } else {
                        throw new Exception("Malicious attacker attempted to use fake ID!");
                    }
                }
            }
        }

        public void shutdown() {
            try {
                in.close();
                out.close();
                if (!this.client.isClosed()) {
                    this.client.close();
                    System.out.println("\nKDC: Connection closed with client: " + this.client.getPort());
                }
            } catch (Exception e) {
                // TODO: handle exception
            }
        }
    }
}
