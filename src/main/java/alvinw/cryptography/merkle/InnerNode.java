package alvinw.cryptography.merkle;

import alvinw.cryptography.CryptoUtils;
import org.jetbrains.annotations.Nullable;

import java.nio.ByteBuffer;
import java.util.stream.Collectors;

public class InnerNode implements Node {
    private InnerNode parent;
    private final Node a;
    private final @Nullable Node b;

    public InnerNode(Node a, @Nullable Node b) {
        this.a = a;
        this.b = b;
        this.a.setParent(this);
        if (this.b != null) {
            this.b.setParent(this);
        }
    }

    @Override
    public byte[] hash() {
        byte[] aHash = this.a.hash();
        byte[] bHash = this.b != null ? this.b.hash() : new byte[0];
        byte[] both = new byte[aHash.length + bHash.length];
        ByteBuffer.wrap(both).put(aHash).put(bHash);
        return CryptoUtils.sha256(both);
    }

    @Override
    public InnerNode getParent() {
        return this.parent;
    }

    @Override
    public void setParent(InnerNode parent) {
        this.parent = parent;
    }

    public Node getA() {
        return this.a;
    }

    public @Nullable Node getB() {
        return this.b;
    }

    @Override
    public String toString() {
        String a = indent(this.a.toString());
        String b = this.b != null ? indent(this.b.toString()) : null;
        return CryptoUtils.hexString(this.hash()) + ":\n" + a + "\n--------AND---------\n" + b;
    }

    private static String indent(String str) {
        return str.lines().map(line -> "    " + line).collect(Collectors.joining("\n"));
    }
}
