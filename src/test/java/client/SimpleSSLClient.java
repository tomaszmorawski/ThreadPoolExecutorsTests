package client;

import java.io.*;
import java.net.Socket;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.security.KeyManagementException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.util.concurrent.TimeUnit;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManagerFactory;

public class SimpleSSLClient implements Runnable {

    private final String ID;
    private final String KEYSTORE_PATH;
    private final String KEYSTORE_PASSWORD;
    private final String TRUSTSTORE_PATH;
    private final String TRUSTSTORE_PASSWORD;

    private final Logger logger = LoggerFactory.getLogger(this.getClass());
    public String serverIP;
    private final int serverPort;

    private SSLSocket s = null;
    private SSLSocketFactory factory;
    private ObjectOutputStream oos;
    private long lastActive;


    private boolean shouldBeConnected = true;

    public SimpleSSLClient(String serverIP, int serverPort, String KEYSTORE_PATH, String KEYSTORE_PASSWORD, String TRUSTSTORE_PATH, String TRUSTSTORE_PASSWORD, String ID) {
        this.serverIP = serverIP;
        this.serverPort = serverPort;
        this.KEYSTORE_PATH = KEYSTORE_PATH;
        this.KEYSTORE_PASSWORD = KEYSTORE_PASSWORD;
        this.TRUSTSTORE_PATH = TRUSTSTORE_PATH;
        this.TRUSTSTORE_PASSWORD = TRUSTSTORE_PASSWORD;
        this.ID = ID;
        createSSSLSocketFactory();
    }

    public void requestDisconnect() {
        shouldBeConnected = false;
        if (s != null) {
            try {
                s.close();
            } catch (Exception e) {
                e.printStackTrace();
                logger.error(e.toString(), e);
            }
            s = null;
        }
    }

    public void requestReconnect() {
        shouldBeConnected = true;
    }

    public void run() {
        try {
            TimeUnit.MILLISECONDS.sleep(100);
            s = (SSLSocket) factory.createSocket(serverIP, serverPort);
            Socket connection = (Socket) s;
            BufferedReader input = new BufferedReader(new InputStreamReader(connection.getInputStream()));
            PrintWriter writer = new PrintWriter(new OutputStreamWriter(connection.getOutputStream()),true);
            System.out.println("Sending ID to server: "+ID);
            writer.println(ID);
            System.out.println("Getting msg form server");
            System.out.println(input.readLine());
            System.out.println("Send quit id:"+ID);
            writer.println("quit");
            closeSocket();
        } catch (IOException | InterruptedException e) {
            e.printStackTrace();
        }
    }


    private void closeSocket() {
        if (s != null) {
            try {
                s.close();
            } catch (Exception e1) {
                e1.printStackTrace();
                logger.error(e1.toString(), e1);
            }
            s = null;
        }
    }

    private void createSSSLSocketFactory() {
        try {
            InputStream keyStoreInputStream = new FileInputStream(KEYSTORE_PATH);
            InputStream trustStoreInputStream = new FileInputStream(TRUSTSTORE_PATH);

            KeyStore keyStore = KeyStore.getInstance("JKS");
            keyStore.load(keyStoreInputStream, KEYSTORE_PASSWORD.toCharArray());
            keyStoreInputStream.close();

            KeyManagerFactory keyManagerFactory = KeyManagerFactory.getInstance("SunX509");
            keyManagerFactory.init(keyStore, KEYSTORE_PASSWORD.toCharArray());

            KeyStore trustStore = KeyStore.getInstance("JKS");
            trustStore.load(trustStoreInputStream, TRUSTSTORE_PASSWORD.toCharArray());
            trustStoreInputStream.close();

            TrustManagerFactory trustManagerFactory = TrustManagerFactory.getInstance("SunX509");
            trustManagerFactory.init(trustStore);

            SSLContext sslContext = SSLContext.getInstance("TLS");
            sslContext.init(keyManagerFactory.getKeyManagers(), trustManagerFactory.getTrustManagers(), new SecureRandom());

            factory = sslContext.getSocketFactory();
        } catch (IOException e) {
            e.printStackTrace();
        } catch (CertificateException e) {
            e.printStackTrace();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (UnrecoverableKeyException e) {
            e.printStackTrace();
        } catch (KeyStoreException e) {
            e.printStackTrace();
        } catch (KeyManagementException e) {
            e.printStackTrace();
        }
    }


}

