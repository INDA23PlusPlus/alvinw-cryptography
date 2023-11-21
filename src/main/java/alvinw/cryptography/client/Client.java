package alvinw.cryptography.client;

import alvinw.cryptography.CryptoUtils;
import alvinw.cryptography.server.Server;

import javax.crypto.SecretKey;
import java.io.IOException;
import java.io.InputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
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

        Client client = new Client(Path.of("run/client"), new URL("http://localhost:" + Server.PORT), password);

        client.upload(Path.of("README.md"));
        client.read("README.md");
    }

    public void upload(Path file) throws IOException, GeneralSecurityException {
        byte[] plainText = Files.readAllBytes(file);

        byte[] nonce = CryptoUtils.randomBytes(16);
        byte[] iv = CryptoUtils.randomBytes(12);
        SecretKey aesKey = CryptoUtils.deriveAesKeyFromPasswordAndNonce(this.password, nonce);

        String fileName = file.getFileName().toString();
        byte[] fileNameHash = CryptoUtils.sha256(fileName.getBytes());

        byte[] cipherText = CryptoUtils.aesGcmEncrypt(aesKey, iv, plainText, fileNameHash);

        URL uploadUrl = new URL(this.serverUrl, "/upload/" + fileName);
        HttpURLConnection req = (HttpURLConnection) uploadUrl.openConnection();
        req.setRequestMethod("POST");
        req.setDoOutput(true);
        req.getOutputStream().write(nonce);
        req.getOutputStream().write(iv);
        req.getOutputStream().write(cipherText);
        req.getOutputStream().close();
        if (req.getResponseCode() != HttpURLConnection.HTTP_CREATED) {
            throw HttpResponseException.of(req);
        }
    }

    public void read(String fileName) throws IOException, GeneralSecurityException {
        URL readUrl = new URL(this.serverUrl, "/read/" + fileName);
        HttpURLConnection req = (HttpURLConnection) readUrl.openConnection();
        if (req.getResponseCode() != HttpURLConnection.HTTP_OK) {
            throw HttpResponseException.of(req);
        }
        InputStream inputStream = req.getInputStream();
        byte[] nonce = inputStream.readNBytes(16);
        byte[] iv = inputStream.readNBytes(12);
        byte[] cipherText = inputStream.readAllBytes();

        byte[] fileNameHash = CryptoUtils.sha256(fileName.getBytes());
        SecretKey aesKey = CryptoUtils.deriveAesKeyFromPasswordAndNonce(this.password, nonce);

        byte[] plainText = CryptoUtils.aesGcmDecrypt(aesKey, iv, cipherText, fileNameHash);

        System.out.write(plainText);
    }
}
