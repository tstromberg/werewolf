import com.sun.net.httpserver.HttpServer;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;

// A test application for the actual jre-app service and its jar entry point.
public final class Main {
    public static void main(String[] args) throws Exception {
        HttpServer server = HttpServer.create(new InetSocketAddress("0.0.0.0", 8080), 0);
        server.createContext("/", exchange -> {
            String path = exchange.getRequestURI().getPath();
            int status;
            String body;
            if (!exchange.getRequestMethod().equals("GET")) {
                status = 405;
                body = "method not allowed\n";
                exchange.getResponseHeaders().set("Allow", "GET");
            } else if (path.equals("/")) {
                status = 200;
                body = "Hello from Java on werewolf!\n";
            } else if (path.equals("/health")) {
                status = 200;
                body = "ok\n";
            } else {
                status = 404;
                body = "not found\n";
            }
            byte[] bytes = body.getBytes(StandardCharsets.UTF_8);
            exchange.getResponseHeaders().set("Content-Type", "text/plain; charset=utf-8");
            exchange.sendResponseHeaders(status, bytes.length);
            exchange.getResponseBody().write(bytes);
            exchange.close();
        });
        server.start();
        System.out.println("app: listening on :8080");
    }
}
