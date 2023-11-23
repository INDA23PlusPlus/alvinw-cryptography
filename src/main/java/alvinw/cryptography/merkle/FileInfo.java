package alvinw.cryptography.merkle;

import alvinw.cryptography.CryptoUtils;

/**
 * Information about a file. Primarily the file's SHA-256 hash, and the
 * file id.
 */
public class FileInfo {
    private final byte[] sha256;
    private final byte[] fileId;

    public FileInfo(byte[] fileId, byte[] content) {
        this.fileId = fileId;
        this.sha256 = CryptoUtils.sha256(content);
    }

    public byte[] getSha256() {
        return sha256;
    }

    public byte[] getFileId() {
        return fileId;
    }
}
