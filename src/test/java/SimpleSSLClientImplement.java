import client.SimpleSSLClient;

import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.ThreadPoolExecutor;

public class SimpleSSLClientImplement {
    public static void main(String[] args) {
        ExecutorService executorService = Executors.newCachedThreadPool();
        List<SimpleSSLClient> clients = new ArrayList<>();
        for (int i = 0; i < 1000; i++) {
            executorService.execute(new SimpleSSLClient("localhost",443,
                    "client.jks","password",
                    "server.jks","password",String.valueOf(i)));
        }
    }
}
