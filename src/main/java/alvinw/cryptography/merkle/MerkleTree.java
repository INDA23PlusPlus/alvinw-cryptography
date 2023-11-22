package alvinw.cryptography.merkle;

import alvinw.cryptography.CryptoUtils;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedList;
import java.util.List;
import java.util.Queue;
import java.util.Set;
import java.util.function.Predicate;
import java.util.stream.Collectors;

public class MerkleTree {
    private final Node rootNode;

    public MerkleTree(Node rootNode) {
        this.rootNode = rootNode;
    }

    public byte[] getTopHash() {
        return this.rootNode.hash();
    }

    public Node find(Predicate<Node> predicate) {
        Queue<Node> queue = new LinkedList<>();
        queue.add(this.rootNode);
        while (!queue.isEmpty()) {
            Node current = queue.poll();
            if (predicate.test(current)) {
                return current;
            }
            if (current instanceof InnerNode innerNode) {
                queue.add(innerNode.getA());
                Node b = innerNode.getB();
                if (b != null) {
                    queue.add(b);
                }
            }
        }
        return null;
    }

    public static MerkleTree fromFiles(Set<FileAndSomethingElseIdk> files) {
        List<FileAndSomethingElseIdk> sortedFiles = files.stream()
            .sorted((o1, o2) -> compareByteArrays(o1.getFileId(), o2.getFileId()))
            .collect(Collectors.toList());

        // If odd amount of files copy last file
        if (sortedFiles.size() % 2 == 1) {
            FileAndSomethingElseIdk lastFile = sortedFiles.get(sortedFiles.size() - 1);
            sortedFiles.add(lastFile);
        }
        List<Node> leafNodes = sortedFiles.stream()
            .map(file -> (Node) new LeafNode(file.getSha256()))
            .toList();

        List<Node> layerNodes = leafNodes;
        while (layerNodes.size() > 1) {
            List<Node> newLayerNodes = new ArrayList<>();
            for (int i = 0; i < layerNodes.size(); i += 2) {
                Node a = layerNodes.get(i);
                Node b =
                    i + 1 < layerNodes.size()
                    ? layerNodes.get(i + 1)
                    : null;
                InnerNode newNode = new InnerNode(a, b);
                newLayerNodes.add(newNode);
            }
            layerNodes = newLayerNodes;
        }
        return new MerkleTree(layerNodes.get(0));
    }

    private static int compareByteArrays(byte[] left, byte[] right) {
        // https://stackoverflow.com/a/5108711
        for (int i = 0, j = 0; i < left.length && j < right.length; i++, j++) {
            int a = (left[i] & 0xff);
            int b = (right[j] & 0xff);
            if (a != b) {
                return a - b;
            }
        }
        return left.length - right.length;
    }

    public static boolean verifyFile(LeafNode fileNode, byte[] topHash, List<ComplementingHash> complementingHashes) {
        Node current = fileNode;

        for (ComplementingHash complementingHash : complementingHashes) {
            byte[] hash = complementingHash.sha256();
            LeafNode complementingNode = hash != null ? new LeafNode(hash) : null;
            Node a;
            Node b;
            if (complementingHash.left()) {
                a = complementingNode;
                b = current;
            } else {
                a = current;
                b = complementingNode;
            }
            current = new InnerNode(a, b);
        }

        // Current is now top node
        byte[] calculatedTopHash = current.hash();
        return Arrays.equals(calculatedTopHash, topHash);
    }

    // https://i.imgur.com/6c5HsdB.png
    public static MerkleTree reconstruct(byte[] dataHash, List<ComplementingHash> hashes) {
        Node current = new LeafNode(dataHash);
        for (ComplementingHash complementingHash : hashes) {
            Node a;
            Node b;
            byte[] hash = complementingHash.sha256();
            LeafNode complementingHashNode = hash != null ? new LeafNode(hash) : null;
            if (complementingHash.left()) {
                a = complementingHashNode;
                b = current;
            } else {
                a = current;
                b = complementingHashNode;
            }
            InnerNode parent = new InnerNode(a, b);
            if (a != null) a.setParent(parent);
            if (b != null) b.setParent(parent);
            current = parent;
        }
        return new MerkleTree(current);
    }

    @Override
    public String toString() {
        return "MerkleTree, root hash: " + CryptoUtils.hexString(this.rootNode.hash()) + ":\n" + this.rootNode;
    }
}
