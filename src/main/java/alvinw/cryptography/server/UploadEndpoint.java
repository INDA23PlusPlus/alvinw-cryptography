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
import java.net.HttpURLConnection;
import java.util.Arrays;
import java.util.List;

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
        byte[] fileId = this.fileStorage.getFileId(fileName);
        byte[] fileContent = exchange.getRequestBody().readAllBytes();
        byte[] sha256 = CryptoUtils.sha256(fileContent);
        this.fileStorage.store(fileId, fileContent);

        System.out.println("fileContent.length = " + fileContent.length);
        System.out.println("sha256 = " + CryptoUtils.hexString(sha256));

        MerkleTree merkleTree = this.fileStorage.getMerkleTree();
        LeafNode leafNode = (LeafNode) merkleTree.find(
            node -> node instanceof LeafNode ln && Arrays.equals(ln.hash(), sha256)
        );
        List<ComplementingHash> complementingHashes = leafNode.getComplementingHashes();

        ByteArrayOutputStream output = new ByteArrayOutputStream();
        DataOutputStream dataOutput = new DataOutputStream(output);
        ComplementingHash.write(complementingHashes, dataOutput);
        byte[] outputBytes = output.toByteArray();

        exchange.sendResponseHeaders(HttpURLConnection.HTTP_CREATED, outputBytes.length);
        exchange.getResponseBody().write(outputBytes);
        exchange.getResponseBody().close();
    }
}
