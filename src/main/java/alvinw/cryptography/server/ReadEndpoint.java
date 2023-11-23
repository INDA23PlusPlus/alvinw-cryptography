package alvinw.cryptography.server;

import alvinw.cryptography.CryptoUtils;
import alvinw.cryptography.merkle.ComplementingHash;
import alvinw.cryptography.merkle.LeafNode;
import alvinw.cryptography.merkle.MerkleTree;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;

import java.io.ByteArrayOutputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.HttpURLConnection;
import java.util.Arrays;
import java.util.List;

/**
 * Http handler for the endpoint that reads files.
 */
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
        byte[] fileId = this.fileStorage.getFileId(fileName);

        byte[] fileContent;
        try (InputStream stream = this.fileStorage.read(fileId)) {
            fileContent = stream.readAllBytes();
        }
        byte[] sha256 = CryptoUtils.sha256(fileContent);

        MerkleTree merkleTree = this.fileStorage.getMerkleTree();
        LeafNode node = (LeafNode) merkleTree.find(
            n -> n instanceof LeafNode leafNode && Arrays.equals(leafNode.hash(), sha256)
        );
        List<ComplementingHash> complementingHashes = node.getComplementingHashes();

        ByteArrayOutputStream output = new ByteArrayOutputStream();
        DataOutputStream dataOutput = new DataOutputStream(output);
        ComplementingHash.write(complementingHashes, dataOutput);
        dataOutput.write(fileContent);
        byte[] outputBytes = output.toByteArray();
        exchange.sendResponseHeaders(HttpURLConnection.HTTP_OK, outputBytes.length);
        exchange.getResponseBody().write(outputBytes);
        exchange.getResponseBody().close();
    }
}
