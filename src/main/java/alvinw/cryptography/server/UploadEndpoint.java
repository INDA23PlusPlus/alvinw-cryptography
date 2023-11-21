package alvinw.cryptography.server;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;

import java.io.IOException;
import java.net.HttpURLConnection;

public class UploadEndpoint implements HttpHandler {
    private final FileStorage fileStorage;

    public UploadEndpoint(FileStorage fileStorage) {
        this.fileStorage = fileStorage;
    }

    @Override
    public void handle(HttpExchange exchange) throws IOException {
        if (!"POST".equals(exchange.getRequestMethod())) {
            exchange.sendResponseHeaders(HttpURLConnection.HTTP_BAD_METHOD, 0);
            exchange.getResponseBody().close();
            return;
        }
        String fileName = exchange.getRequestURI().getPath().substring("/upload/".length());
        this.fileStorage.store(fileName, exchange.getRequestBody());
        exchange.sendResponseHeaders(HttpURLConnection.HTTP_CREATED, -1);
        exchange.getResponseBody().close();
    }
}
