import server.SimpleSSLServer;

public class ServerImplement {
    public static void main(String[] args) {
        SimpleSSLServer server = new SimpleSSLServer(443,
                "server.jks","password",
                "server.jks","password");
        server.run();
    }
}
