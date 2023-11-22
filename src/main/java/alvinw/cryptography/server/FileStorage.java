package alvinw.cryptography.server;

import alvinw.cryptography.CryptoUtils;
import alvinw.cryptography.merkle.FileAndSomethingElseIdk;
import alvinw.cryptography.merkle.MerkleTree;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Set;
import java.util.stream.Collectors;

public class FileStorage {
    private final Path root;

    public FileStorage(Path root) {
        this.root = root;
    }

    private Path getPath(byte[] fileId) {
        String hex = CryptoUtils.hexString(fileId);
        return this.root.resolve(hex + ".bin");
    }

    public byte[] getFileId(String fileName) {
        return CryptoUtils.sha256(fileName.getBytes(StandardCharsets.UTF_8));
    }

    public void store(byte[] fileId, byte[] fileContent) throws IOException {
        Path path = this.getPath(fileId);
        Files.write(path, fileContent);
    }

    public InputStream read(byte[] fileId) throws IOException {
        Path path = this.getPath(fileId);
        return Files.newInputStream(path);
    }

    public Set<byte[]> getFiles() throws IOException {
        return Files.list(this.root)
            .filter(path -> path.toString().endsWith(".bin"))
            .map(path -> path.getFileName().toString())
            .map(name -> name.substring(0, name.length() -  ".bin".length()))
            .map(CryptoUtils::fromHex)
            .collect(Collectors.toSet());
    }

    public MerkleTree getMerkleTree() throws IOException {
        Set<FileAndSomethingElseIdk> files = this.getFiles().stream()
            .map(fileId -> {
                try (InputStream inputStream = this.read(fileId)) {
                    return new FileAndSomethingElseIdk(fileId, inputStream.readAllBytes());
                } catch (IOException e) {
                    throw new RuntimeException(e);
                }
            }).collect(Collectors.toSet());

        return MerkleTree.fromFiles(files);
    }
}
