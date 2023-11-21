package alvinw.cryptography.server;

import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;

public class FileStorage {
    private final Path root;

    public FileStorage(Path root) {
        this.root = root;
    }

    private Path getPath(String fileName) {
        return this.root.resolve(fileName + ".bin");
    }

    public void store(String fileName, InputStream inputStream) throws IOException {
        Path path = this.getPath(fileName);
        Files.copy(inputStream, path, StandardCopyOption.REPLACE_EXISTING);
    }

    public InputStream read(String fileName) throws IOException {
        Path path = this.getPath(fileName);
        return Files.newInputStream(path);
    }

    public long size(String fileName) throws IOException {
        Path path = this.getPath(fileName);
        return Files.size(path);
    }
}
