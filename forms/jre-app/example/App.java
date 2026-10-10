// A stand-in for the jar a jre-app machine runs. It answers on port 8080.
import com.sun.net.httpserver.HttpServer;
import java.net.InetSocketAddress;

public class App {
	public static void main(String[] args) throws Exception {
		HttpServer server = HttpServer.create(new InetSocketAddress("0.0.0.0", 8080), 0);
		server.createContext("/", exchange -> {
			byte[] body = "ok\n".getBytes("UTF-8");
			exchange.sendResponseHeaders(200, body.length);
			exchange.getResponseBody().write(body);
			exchange.close();
		});
		server.start();
	}
}
