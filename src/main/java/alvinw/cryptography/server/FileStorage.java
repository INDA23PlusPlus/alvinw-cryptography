package alvinw.cryptography.server;

import alvinw.cryptography.CryptoUtils;
import alvinw.cryptography.merkle.FileInfo;
import alvinw.cryptography.merkle.MerkleTree;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Set;
import java.util.stream.Collectors;

/**
 * The server's file storage.
 */
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

    /**
     * Get the set of file ids (SHA-256 hashes).
     *
     * @return The set.
     * @throws IOException If an I/O error occurs.
     */
    public Set<byte[]> getFiles() throws IOException {
        return Files.list(this.root)
            .filter(path -> path.toString().endsWith(".bin"))
            .map(path -> path.getFileName().toString())
            .map(name -> name.substring(0, name.length() -  ".bin".length()))
            .map(CryptoUtils::fromHex)
            .collect(Collectors.toSet());
    }

    /**
     * Get the Merkle tree from all the files in the storage.
     *
     * @return The Merkle tree.
     * @throws IOException If an I/O error occurs.
     */
    public MerkleTree getMerkleTree() throws IOException {
        Set<FileInfo> files = this.getFiles().stream()
            .map(fileId -> {
                try (InputStream inputStream = this.read(fileId)) {
                    return new FileInfo(fileId, inputStream.readAllBytes());
                } catch (IOException e) {
                    throw new RuntimeException(e);
                }
            }).collect(Collectors.toSet());

        return MerkleTree.fromFiles(files);
    }
}
