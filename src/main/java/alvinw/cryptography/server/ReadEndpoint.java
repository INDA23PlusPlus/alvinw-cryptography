package alvinw.cryptography.server;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;

import java.io.IOException;
import java.io.InputStream;
import java.net.HttpURLConnection;

public class ReadEndpoint implements HttpHandler {
    private final FileStorage fileStorage;

    public ReadEndpoint(FileStorage fileStorage) {
        this.fileStorage = fileStorage;
    }

    @Override
    public void handle(HttpExchange exchange) throws IOException {
        if (!"GET".equals(exchange.getRequestMethod())) {
            exchange.sendResponseHeaders(HttpURLConnection.HTTP_BAD_METHOD, 0);
            exchange.getResponseBody().close();
            return;
        }
        String fileName = exchange.getRequestURI().getPath().substring("/read/".length());
        try (InputStream stream = this.fileStorage.read(fileName)) {
            exchange.sendResponseHeaders(HttpURLConnection.HTTP_OK, this.fileStorage.size(fileName));
            stream.transferTo(exchange.getResponseBody());
            exchange.getResponseBody().close();
        }
    }
}
