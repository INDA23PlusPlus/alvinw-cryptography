package alvinw.cryptography.merkle;

import alvinw.cryptography.CryptoUtils;

public class FileAndSomethingElseIdk {
    private final byte[] content;
    private final byte[] sha256;
    private final byte[] fileId;

    public FileAndSomethingElseIdk(byte[] fileId, byte[] content) {
        this.fileId = fileId;
        this.content = content;
        this.sha256 = CryptoUtils.sha256(content);
    }

    public byte[] getSha256() {
        return sha256;
    }

    public byte[] getFileId() {
        return fileId;
    }
}
