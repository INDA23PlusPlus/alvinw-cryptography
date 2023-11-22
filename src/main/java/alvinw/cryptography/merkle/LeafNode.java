package alvinw.cryptography.merkle;

import alvinw.cryptography.CryptoUtils;
import org.jetbrains.annotations.NotNull;

import java.util.ArrayList;
import java.util.List;

public final class LeafNode implements Node {
    private InnerNode parent;
    private final byte[] hash;

    public LeafNode(byte @NotNull [] hash) {
        this.hash = hash;
    }

    @Override
    public InnerNode getParent() {
        return this.parent;
    }

    @Override
    public void setParent(InnerNode parent) {
        this.parent = parent;
    }

    @Override
    public byte[] hash() {
        return hash;
    }

    @Override
    public String toString() {
        return CryptoUtils.hexString(this.hash);
    }

    public List<ComplementingHash> getComplementingHashes() {
        List<ComplementingHash> complementingHashes = new ArrayList<>();
        Node current = this;
        while (true) {
            InnerNode parent = current.getParent();
            if (parent == null) {
                break;
            }
            Node a = parent.getA();
            Node b = parent.getB();
            if (current == a) {
                complementingHashes.add(new ComplementingHash(
                    false, b != null ? b.hash() : null
                ));
            } else if (current == b) {
                complementingHashes.add(new ComplementingHash(
                    true, a.hash()
                ));
            } else {
                throw new IllegalStateException("Invalid Merkle tree");
            }
            current = parent;
        }
        return complementingHashes;
    }

}
