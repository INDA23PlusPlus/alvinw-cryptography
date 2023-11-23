package alvinw.cryptography.merkle;

import alvinw.cryptography.CryptoUtils;
import org.jetbrains.annotations.Nullable;

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

/**
 * A complementing hash in a Merkle tree.
 *
 * @param left True if the complementing hash is the left one, false if the right one.
 * @param sha256 The SHA-256.
 */
public record ComplementingHash(boolean left, @Nullable byte @Nullable [] sha256) {
    /**
     * Read a list of complementing hashes.
     *
     * @param dataInput The data input to read from.
     * @return The list.
     * @throws IOException If an I/O error occurs.
     */
    public static List<ComplementingHash> read(DataInputStream dataInput) throws IOException {
        int size = dataInput.readInt();
        List<ComplementingHash> complementingHashes = new ArrayList<>(size);
        for (int i = 0; i < size; i++) {
            boolean left = dataInput.readBoolean();
            boolean isPresent = dataInput.readBoolean();
            byte[] hash = isPresent ? new byte[256 / 8] : null;
            if (isPresent) {
                dataInput.readFully(hash);
            }
            ComplementingHash complementingHash = new ComplementingHash(left, hash);
            complementingHashes.add(complementingHash);
        }
        return complementingHashes;
    }

    @Override
    public String toString() {
        return "ComplementingHash{" +
            "left=" + left +
            ", sha256=" + CryptoUtils.hexString(sha256) +
            '}';
    }

    /**
     * Write a list of complementing hashes.
     *
     * @param complementingHashes The list.
     * @param dataOutput The output to write to.
     * @throws IOException If an I/O error occurs.
     */
    public static void write(List<ComplementingHash> complementingHashes, DataOutputStream dataOutput) throws IOException {
        dataOutput.writeInt(complementingHashes.size());
        for (ComplementingHash complementingHash : complementingHashes) {
            dataOutput.writeBoolean(complementingHash.left());
            byte[] hash = complementingHash.sha256();
            dataOutput.writeBoolean(hash != null);
            if (hash != null) {
                dataOutput.write(hash);
            }
        }
    }
}
