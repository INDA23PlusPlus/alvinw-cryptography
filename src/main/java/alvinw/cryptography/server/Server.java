package alvinw.cryptography.server;

import com.sun.net.httpserver.HttpServer;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.nio.file.Files;
import java.nio.file.Path;

public class Server {
    public static final int PORT = 4146;

    private final Path root;

    public Server(Path root) {
        this.root = root;
    }

    public static void main(String[] args) throws IOException {
        new Server(Path.of("run/server")).start();
    }

    public void start() throws IOException {
        Path storagePath = this.root.resolve("storage");
        Files.createDirectories(storagePath);
        FileStorage fileStorage = new FileStorage(storagePath);

        HttpServer httpServer = HttpServer.create(new InetSocketAddress(PORT), 0);

        httpServer.createContext("/upload/", new UploadEndpoint(fileStorage));
        httpServer.createContext("/read/", new ReadEndpoint(fileStorage));
        httpServer.createContext("/verify", new VerifyEndpoint(fileStorage));

        httpServer.start();
        System.out.println("Running on port " + PORT);
    }
}
