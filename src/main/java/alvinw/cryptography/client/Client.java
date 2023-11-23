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
import java.io.DataOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Arrays;
import java.util.List;
import java.util.Scanner;

/**
 * A client that can connect to the server and upload, read, and verify files.
 */
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

    public void generateKeyPair() throws NoSuchAlgorithmException, IOException {
        System.out.println("Generating key pair...");
        KeyPair keyPair = CryptoUtils.generateKeyPair();

        // Store keys
        Files.write(this.root.resolve("private_key.bin"), keyPair.getPrivate().getEncoded());
        Files.write(this.root.resolve("public_key.pub"), keyPair.getPublic().getEncoded());
    }

    public PublicKey getPublicKey() throws IOException, GeneralSecurityException {
        Path path = this.root.resolve("public_key.pub");
        if (Files.notExists(path)) {
            this.generateKeyPair();
        }
        byte[] bytes = Files.readAllBytes(path);
        return CryptoUtils.readPublicKey(bytes);
    }

    public PrivateKey getPrivateKey() throws IOException, GeneralSecurityException {
        Path path = this.root.resolve("private_key.bin");
        if (Files.notExists(path)) {
            this.generateKeyPair();
        }
        byte[] bytes = Files.readAllBytes(path);
        return CryptoUtils.readPrivateKey(bytes);
    }

    public void upload(Path file) throws IOException, GeneralSecurityException {
        byte[] plainText = Files.readAllBytes(file);

        // Generate random nonce and iv.
        // Nonce ensures aes key differs for each file.
        // iv = initial values for AES-GCM.
        byte[] nonce = CryptoUtils.randomBytes(16);
        byte[] iv = CryptoUtils.randomBytes(12);
        SecretKey aesKey = CryptoUtils.deriveAesKeyFromPasswordAndNonce(this.password, nonce);

        // Calculate file id as the hash of the file name.
        // The file id is then passed as additional data to AES-GCM.
        String fileName = file.getFileName().toString();
        byte[] fileNameHash = CryptoUtils.sha256(fileName.getBytes());

        // Encrypt!
        byte[] cipherText = CryptoUtils.aesGcmEncrypt(aesKey, iv, plainText, fileNameHash);

        ByteArrayOutputStream output = new ByteArrayOutputStream();
        DataOutputStream dataOutput = new DataOutputStream(output);
        dataOutput.write(nonce);
        dataOutput.write(iv);
        dataOutput.writeLong(System.currentTimeMillis()); // prevent replay
        dataOutput.write(cipherText);
        byte[] outputBytes = output.toByteArray();

        // Calculate the SHA-256 of the none, iv, timestamp and ciphertext.
        // This is the SHA-256 hash that we sign.
        byte[] innerSha256 = CryptoUtils.sha256(outputBytes);

        // Sign the inner SHA-256 hash.
        byte[] signature = CryptoUtils.signWithRsa(this.getPrivateKey(), innerSha256);

        // Prepare sending the request to the server.
        URL uploadUrl = new URL(this.serverUrl, "/upload/" + fileName);
        HttpURLConnection req = (HttpURLConnection) uploadUrl.openConnection();
        req.setRequestMethod("POST");
        req.setDoOutput(true);
        ByteArrayOutputStream finalBAOS = new ByteArrayOutputStream();
        DataOutputStream finalOutput = new DataOutputStream(finalBAOS);

        // Write the signature before the other data
        finalOutput.writeInt(signature.length);
        finalOutput.write(signature);

        // Write the other output
        finalOutput.write(outputBytes);

        // Send the data to the server.
        byte[] finalOutputBytes = finalBAOS.toByteArray();
        req.getOutputStream().write(finalOutputBytes);
        req.getOutputStream().close();
        if (req.getResponseCode() != HttpURLConnection.HTTP_CREATED) {
            throw HttpResponseException.of(req);
        }

        // The server replies with the complementing hashes in the Merkle tree so that
        // we can calculate the new top hash. Note that the server only needs to send
        // log2(n) hashes instead of hashes of all files.

        InputStream input = req.getInputStream();
        DataInputStream dataInput = new DataInputStream(input);
        List<ComplementingHash> complementingHashes = ComplementingHash.read(dataInput);

        // Calculate the SHA-256 of the entire file, including the prefixed signature.
        // This is the same SHA-256 hash that the server uses to calculate the
        // Merkle-tree.
        byte[] sha256 = CryptoUtils.sha256(finalOutputBytes);

        // We can now reconstruct the Merkle tree from the file hash and the
        // complementing hashes we got.
        MerkleTree merkleTree = MerkleTree.reconstruct(sha256, complementingHashes);

        // Update the top hash of the Merkle tree. This can now be used in the future
        // to validate that the file tree on the server is correct.
        setClientTopHash(merkleTree.getTopHash());
    }

    public void read(String fileName) throws IOException, GeneralSecurityException {
        // Send the request
        URL readUrl = new URL(this.serverUrl, "/read/" + fileName);
        HttpURLConnection req = (HttpURLConnection) readUrl.openConnection();
        if (req.getResponseCode() != HttpURLConnection.HTTP_OK) {
            throw HttpResponseException.of(req);
        }
        DataInputStream dataInput = new DataInputStream(req.getInputStream());

        // The server first sends the complementing hashes so that we can recalculate
        // the top hash and compare it to the one stored locally to ensure that the file
        // we are reading has not been changed by the server.
        List<ComplementingHash> complementingHashes = ComplementingHash.read(dataInput);

        // Calculate the SHA-256 of the entire data, including the signature, as this is
        // used in the Merkle tree.
        byte[] totalData = dataInput.readAllBytes();
        byte[] sha256 = CryptoUtils.sha256(totalData);

        // Verify the file using the Merkle tree.
        LeafNode fileNode = new LeafNode(sha256);
        if (MerkleTree.verifyFile(fileNode, this.getClientTopHash(), complementingHashes)) {
            System.out.println("File verified. Top hash matches.");
        } else {
            System.out.println("Failed to validate file! Top hash does not line up.");
        }

        DataInputStream data = new DataInputStream(new ByteArrayInputStream(totalData));
        // Read the signature.
        int signatureSize = data.readInt();
        byte[] signature = data.readNBytes(signatureSize);

        // The signature signs the SHA-256 of the inner content. So calculate that hash
        // from the remaining bytes.
        byte[] innerDataBytes = data.readAllBytes();
        byte[] innerSha256 = CryptoUtils.sha256(innerDataBytes);

        // Verify the signature. This ensures that the file was actually uploaded by
        // this client, as no one else could have created a valid signature since that
        // requires access to the private key.
        // Since signing is done with the private key, we use the public key to validate
        // the signature.
        if (CryptoUtils.verifyWithRsa(this.getPublicKey(), innerSha256, signature)) {
            System.out.println("File verified (with signature). Signature is correct.");
        } else {
            System.out.println("Failed to validate file! Signature is not correct.");
        }

        DataInputStream innerData = new DataInputStream(new ByteArrayInputStream(innerDataBytes));
        // Read the nonce, iv, timestamp and ciphertext.
        // While we don't use the timestamp here, it needs to be in the data so that the
        // signature also signs the timestamp.
        byte[] nonce = innerData.readNBytes(16);
        byte[] iv = innerData.readNBytes(12);
        innerData.readLong(); // Read/skip timestamp
        byte[] cipherText = innerData.readAllBytes();

        // Calculate the symmetric key used for encryption so that we can decrypt.
        SecretKey aesKey = CryptoUtils.deriveAesKeyFromPasswordAndNonce(this.password, nonce);

        // Calculate the file id since that is used as additional data in AES-GCM.
        byte[] fileNameHash = CryptoUtils.sha256(fileName.getBytes());

        // Decrypt!
        byte[] plainText = CryptoUtils.aesGcmDecrypt(aesKey, iv, cipherText, fileNameHash);

        System.out.write(plainText);
    }

    private void verify() throws IOException {
        // Send the request
        URL readUrl = new URL(this.serverUrl, "/verify");
        HttpURLConnection req = (HttpURLConnection) readUrl.openConnection();
        if (req.getResponseCode() != HttpURLConnection.HTTP_OK) {
            throw HttpResponseException.of(req);
        }
        // Read the server's top hash and compare to the local one.
        byte[] topHash = req.getInputStream().readAllBytes();
        byte[] clientTopHash = this.getClientTopHash();
        if (Arrays.equals(topHash, clientTopHash)) {
            System.out.println("Verification successful!");
        } else {
            System.out.println("Hash differs!!! Server might have modified our files!");
        }
    }

}
