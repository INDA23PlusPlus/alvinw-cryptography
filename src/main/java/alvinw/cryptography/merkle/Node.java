package alvinw.cryptography.merkle;

public interface Node {
    /**
     * Get the SHA-256 hash of this node.
     *
     * @return The SHA-256 hash.
     */
    byte[] hash();

    /**
     * Get the parent node.
     *
     * @return The parent node, or null.
     */
    InnerNode getParent();

    /**
     * Set the parent node.
     *
     * @param parent The parent node.
     */
    void setParent(InnerNode parent);
}
