package alvinw.cryptography.client;

import alvinw.cryptography.CryptoUtils;
import alvinw.cryptography.merkle.ComplementingHash;
import alvinw.cryptography.merkle.LeafNode;
import alvinw.cryptography.merkle.MerkleTree;
import alvinw.cryptography.server.Server;
import org.jetbrains.annotations.Nullable;

import javax.crypto.SecretKey;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.util.Arrays;
import java.util.List;
import java.util.Scanner;

public class Client {
    private final Path root;
    private final URL serverUrl;
    private final String password;

    public Client(Path root, URL serverUrl, String password) {
        this.root = root;
        this.serverUrl = serverUrl;
        this.password = password;
    }

    public static void main(String[] args) throws IOException, GeneralSecurityException {
        Scanner scanner = new Scanner(System.in);
        System.out.print("Enter client password: ");
        String password = scanner.nextLine().trim();

        Path root = Path.of("run/client");
        Files.createDirectories(root);
        Client client = new Client(root, new URL("http://localhost:" + Server.PORT), password);

        label:
        while (true) {
            System.out.println("What do you want to do?");
            System.out.println("(upload, read, verify, exit)");
            String action = scanner.nextLine().trim();
            if ("exit".equals(action)) {
                break;
            }
            switch (action) {
                case "upload" -> {
                    System.out.println("Enter the path of the file to upload:");
                    Path path = Path.of(scanner.nextLine().trim());
                    if (Files.notExists(path)) {
                        System.err.println("File not found.");
                        break label;
                    }
                    client.upload(path);
                }
                case "read" -> {
                    System.out.println("Enter the file name of the file to read:");
                    String fileName = scanner.nextLine().trim();
                    System.out.println();
                    try {
                        client.read(fileName);
                    } catch (GeneralSecurityException e) {
                        System.err.println("Failed to decrypt");
                        System.err.println("error message: " + e);
                    }
                    System.out.println();
                }
                case "verify" -> client.verify();
                default -> System.err.println("Unrecognized option.");
            }
        }
    }

    public byte @Nullable [] getClientTopHash() throws IOException {
        Path path = this.root.resolve("top_hash.bin");
        if (Files.exists(path)) {
            byte[] bytes = Files.readAllBytes(path);
            if (bytes.length == 256 / 8) {
                return bytes;
            }
        }
        return null;
    }

    public void setClientTopHash(byte @Nullable[] hash) throws IOException {
        Path path = this.root.resolve("top_hash.bin");
        if (hash == null) {
            Files.deleteIfExists(path);
        } else {
            Files.write(path, hash);
        }
    }

    public void upload(Path file) throws IOException, GeneralSecurityException {
        byte[] plainText = Files.readAllBytes(file);

        byte[] nonce = CryptoUtils.randomBytes(16);
        byte[] iv = CryptoUtils.randomBytes(12);
        SecretKey aesKey = CryptoUtils.deriveAesKeyFromPasswordAndNonce(this.password, nonce);

        String fileName = file.getFileName().toString();
        byte[] fileNameHash = CryptoUtils.sha256(fileName.getBytes());

        byte[] cipherText = CryptoUtils.aesGcmEncrypt(aesKey, iv, plainText, fileNameHash);

        ByteArrayOutputStream output = new ByteArrayOutputStream();
        output.write(nonce);
        output.write(iv);
        output.write(cipherText);
        byte[] outputBytes = output.toByteArray();
        byte[] sha256 = CryptoUtils.sha256(outputBytes);

        URL uploadUrl = new URL(this.serverUrl, "/upload/" + fileName);
        HttpURLConnection req = (HttpURLConnection) uploadUrl.openConnection();
        req.setRequestMethod("POST");
        req.setDoOutput(true);
        req.getOutputStream().write(outputBytes);
        req.getOutputStream().close();
        if (req.getResponseCode() != HttpURLConnection.HTTP_CREATED) {
            throw HttpResponseException.of(req);
        }
        InputStream input = req.getInputStream();
        DataInputStream dataInput = new DataInputStream(input);
        List<ComplementingHash> complementingHashes = ComplementingHash.read(dataInput);
        MerkleTree merkleTree = MerkleTree.reconstruct(sha256, complementingHashes);
        setClientTopHash(merkleTree.getTopHash());
    }

    public void read(String fileName) throws IOException, GeneralSecurityException {
        URL readUrl = new URL(this.serverUrl, "/read/" + fileName);
        HttpURLConnection req = (HttpURLConnection) readUrl.openConnection();
        if (req.getResponseCode() != HttpURLConnection.HTTP_OK) {
            throw HttpResponseException.of(req);
        }
        DataInputStream dataInput = new DataInputStream(req.getInputStream());
        List<ComplementingHash> complementingHashes = ComplementingHash.read(dataInput);

        byte[] totalData = dataInput.readAllBytes();
        byte[] sha256 = CryptoUtils.sha256(totalData);
        LeafNode fileNode = new LeafNode(sha256);
        if (!MerkleTree.verifyFile(fileNode, this.getClientTopHash(), complementingHashes)) {
            System.out.println("Failed to validate file! Top hash does not line up.");
        } else {
            System.out.println("File verified. Top hash matches.");
        }

        ByteArrayInputStream data = new ByteArrayInputStream(totalData);
        byte[] nonce = data.readNBytes(16);
        byte[] iv = data.readNBytes(12);
        byte[] cipherText = data.readAllBytes();

        byte[] fileNameHash = CryptoUtils.sha256(fileName.getBytes());
        SecretKey aesKey = CryptoUtils.deriveAesKeyFromPasswordAndNonce(this.password, nonce);

        byte[] plainText = CryptoUtils.aesGcmDecrypt(aesKey, iv, cipherText, fileNameHash);

        System.out.write(plainText);
    }

    private void verify() throws IOException {
        URL readUrl = new URL(this.serverUrl, "/verify");
        HttpURLConnection req = (HttpURLConnection) readUrl.openConnection();
        if (req.getResponseCode() != HttpURLConnection.HTTP_OK) {
            throw HttpResponseException.of(req);
        }
        byte[] topHash = req.getInputStream().readAllBytes();
        byte[] clientTopHash = this.getClientTopHash();
        if (Arrays.equals(topHash, clientTopHash)) {
            System.out.println("Verification successful!");
        } else {
            System.out.println("Hash differs!!! Server might have modified our files!");
        }
    }

}
