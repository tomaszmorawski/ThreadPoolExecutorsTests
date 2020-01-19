package server;

import com.sun.xml.internal.bind.v2.model.core.ID;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.net.ssl.*;
import java.io.*;
import java.security.KeyStore;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.concurrent.*;

public class SimpleSSLServer implements Runnable {

    private final Logger logger = LoggerFactory.getLogger(this.getClass());

    private final int sslPort;
    private final String KEYSTORE_PATH;
    private final String KEYSTORE_PASSWORD;
    private final String TRUSTSTORE_PATH;
    private final String TRUSTSTORE_PASSWORD;
    private SSLServerSocketFactory factory;
    private long listTimeModTrust;

    public SimpleSSLServer(int sslPort, String keystore_path, String keystore_password, String truststore_path, String truststore_password) {
        this.sslPort = sslPort;
        KEYSTORE_PATH = keystore_path;
        KEYSTORE_PASSWORD = keystore_password;
        TRUSTSTORE_PATH = truststore_path;
        TRUSTSTORE_PASSWORD = truststore_password;
    }


    public void run() {
        try {
            createSSLServerSocketFactory();
            final SSLServerSocket sslServerSocket = (SSLServerSocket) factory.createServerSocket(sslPort);
            ThreadPoolExecutor executorService = new ThreadPoolExecutor(300,300,0L,TimeUnit.MILLISECONDS,new ArrayBlockingQueue<Runnable>(1000));
            while (true) {
                SSLSocket socket = (SSLSocket) sslServerSocket.accept();
                socket.setNeedClientAuth(true);
                executorService.execute(new ServerMSG(socket));
                System.out.println(executorService.getActiveCount() + " : " + executorService.getTaskCount() + " : " + executorService.getTaskCount());
            }
        } catch (Exception e) {
            e.printStackTrace();
            logger.error(e.toString(), e);
        }
    }

    private class ServerMSG implements Runnable {
        private SSLSocket socket;

        ServerMSG(SSLSocket socket) {
            this.socket = socket;
        }

        @Override
        public void run() {
            String msg = null;
            System.out.println("start communication");
            BufferedReader bufferedReader = null;
            PrintWriter printWriter = null;
            try {
                bufferedReader = new BufferedReader(new InputStreamReader(socket.getInputStream()));
                printWriter = new PrintWriter(socket.getOutputStream(), true);
            } catch (IOException e) {
                e.printStackTrace();
            }
            try {
                while (!(msg = bufferedReader.readLine()).contains("quit") && socket.isConnected()) {
                    System.out.println("Reading msg from client");
                    System.out.println(msg);
                    SendMsg sendMsg = new SendMsg(printWriter);
                    System.out.println("Sending msg: "+msg);
                    sendMsg.setMSG(msg);
                    sendMsg.start();

                }
                if(msg.contains("quit")){
                    System.out.println("Quiting socket");
                    socket.close();
                }
            } catch (Exception e) {
                e.printStackTrace();
                logger.error(e.toString(), e);
            }
            try {
                socket.close();
            } catch (IOException e) {
                e.printStackTrace();
            }

        }


        private class SendMsg extends Thread {
            private PrintWriter writer;
            private String msg = null;

            SendMsg(PrintWriter writer) {
                this.writer = writer;
            }

            public void setMSG(String msg) {
                this.msg = msg;
            }

            @Override
            public void run() {

                try {
                    int sleepTime = (int)(Math.random()*10000)+1000;
                    TimeUnit.MILLISECONDS.sleep(sleepTime);
                    System.out.println("sending msg client: " + msg + " client after "+sleepTime+"ms");
                    writer.println("hello client it you msg: " + msg);

                } catch (InterruptedException e) {
                    e.printStackTrace();
                }


            }
        }
    }


    private void createSSLServerSocketFactory() {
        try {
            factory = getSSLContext(TRUSTSTORE_PATH).getServerSocketFactory();
        } catch (Exception e) {
            logger.error(e.toString(), e);
            e.printStackTrace();
        }
    }

    public SSLContext getSSLContext(String pathToTrustStore) throws Exception {
        InputStream keyStoreInputStream = new FileInputStream(KEYSTORE_PATH);
        KeyStore keyStore = KeyStore.getInstance("JKS");
        keyStore.load(keyStoreInputStream, KEYSTORE_PASSWORD.toCharArray());
        keyStoreInputStream.close();

        KeyManagerFactory keyManagerFactory = KeyManagerFactory.getInstance("SunX509");
        keyManagerFactory.init(keyStore, KEYSTORE_PASSWORD.toCharArray());

        TrustManager[] trustManagers = new TrustManager[]{
                new ReloadableX509TrustManager(pathToTrustStore)
        };
        SSLContext sslContext = SSLContext.getInstance("TLSv1.2");
        sslContext.init(keyManagerFactory.getKeyManagers(), trustManagers, new SecureRandom());
        return sslContext;
    }

    class ReloadableX509TrustManager implements X509TrustManager {
        private final String trustStorePath;
        private X509TrustManager trustManager;

        public ReloadableX509TrustManager(String pathToTrustStore) throws Exception {
            this.trustStorePath = pathToTrustStore;
            reloadTrustManager();
        }

        @Override
        public void checkClientTrusted(X509Certificate[] x509Certificates, String s) throws CertificateException {
            if (checkTimeTruststore()) {
                try {
                    reloadTrustManager();
                } catch (Exception e) {
                    e.printStackTrace();
                }
            }
            String username = x509Certificates[0].getSubjectDN().getName().split("CN=")[1].split(",")[0];
            x509Certificates[0].checkValidity();
            logger.info("Trying to connect : " + username);
            trustManager.checkClientTrusted(x509Certificates, s);
            x509Certificates[0].checkValidity();
            logger.info("User " + username + " signed in, you are authenticated!");
        }


        @Override
        public void checkServerTrusted(X509Certificate[] x509Certificates, String s) throws CertificateException {
//            trustManager.checkServerTrusted(x509Certificates, s);
        }

        @Override
        public X509Certificate[] getAcceptedIssuers() {
            X509Certificate[] issuers = trustManager.getAcceptedIssuers();
            return issuers;
        }

        private void reloadTrustManager() throws Exception {
            listTimeModTrust = new File(trustStorePath).lastModified();
            KeyStore trustStore = KeyStore.getInstance("JKS");
            InputStream in = new FileInputStream(trustStorePath);
            try {
                trustStore.load(in, TRUSTSTORE_PASSWORD.toCharArray());
            } finally {
                in.close();
            }

            TrustManagerFactory trustManagerFactory = TrustManagerFactory.getInstance("SunX509");
            trustManagerFactory.init(trustStore);

            TrustManager trustManagers[] = trustManagerFactory.getTrustManagers();
            for (int i = 0; i < trustManagers.length; i++) {
                if (trustManagers[i] instanceof X509TrustManager) {
                    trustManager = (X509TrustManager) trustManagers[i];
                    return;
                }
            }
            throw new NoSuchAlgorithmException("No X509TrustManager in TrustManagerFactory");
        }

        private boolean checkTimeTruststore() {
            boolean isNewVersion = false;
            File file = new File(TRUSTSTORE_PATH);
            Long lastTime = file.lastModified();
            if (lastTime != listTimeModTrust) {
                isNewVersion = true;
            }
            return isNewVersion;
        }

    }
}
