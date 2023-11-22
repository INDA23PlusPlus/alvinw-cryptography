package alvinw.cryptography.server;

import alvinw.cryptography.merkle.MerkleTree;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;

import java.io.IOException;
import java.net.HttpURLConnection;

public class VerifyEndpoint implements HttpHandler {
    private final FileStorage fileStorage;

    public VerifyEndpoint(FileStorage fileStorage) {
        this.fileStorage = fileStorage;
    }

    @Override
    public void handle(HttpExchange exchange) throws IOException {
        if (!"GET".equals(exchange.getRequestMethod())) {
            exchange.sendResponseHeaders(HttpURLConnection.HTTP_BAD_METHOD, 0);
            exchange.getResponseBody().close();
            return;
        }
        MerkleTree merkleTree = this.fileStorage.getMerkleTree();
        System.out.println("merkleTree = " + merkleTree);
        exchange.sendResponseHeaders(HttpURLConnection.HTTP_OK, 256 / 8);
        exchange.getResponseBody().write(merkleTree.getTopHash());
        exchange.getResponseBody().close();
    }
}
