package alvinw.cryptography;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.spec.EncodedKeySpec;
import java.security.spec.KeySpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import java.util.HexFormat;

/**
 * Crypto utilities used to encrypt, decrypt, hash, sign, etc.
 */
public class CryptoUtils {
    public static final String AES_GCM_ALGO = "AES/GCM/NoPadding";
    public static final String AES_ALGO = "AES";
    public static final String PBKDF2_ALGO = "PBKDF2WithHmacSHA256";
    public static final String SHA_256_ALGO = "SHA-256";
    public static final String RSA_ALGO = "RSA";
    public static final int RSA_SIZE = 2048;

    public static byte[] randomBytes(int length) {
        byte[] nonce = new byte[length];
        new SecureRandom().nextBytes(nonce);
        return nonce;
    }

    public static SecretKey deriveAesKeyFromPasswordAndNonce(String password, byte[] nonce) throws GeneralSecurityException {
        SecretKeyFactory factory = SecretKeyFactory.getInstance(PBKDF2_ALGO);
        KeySpec spec = new PBEKeySpec(password.toCharArray(), nonce, 65536, 256);
        return new SecretKeySpec(factory.generateSecret(spec).getEncoded(), AES_ALGO);
    }

    public static byte[] sha256(byte[] content) {
        try {
            MessageDigest sha256 = MessageDigest.getInstance(SHA_256_ALGO);
            return sha256.digest(content);
        } catch (NoSuchAlgorithmException e) {
            // All Java implementations are forced to implement SHA-256. Should never throw.
            throw new RuntimeException(e);
        }
    }

    public static byte[] aesGcmEncrypt(SecretKey key, byte[] iv, byte[] plainText, byte[] associatedData) throws GeneralSecurityException {
        Cipher cipher = Cipher.getInstance(AES_GCM_ALGO);
        cipher.init(Cipher.ENCRYPT_MODE, key, new GCMParameterSpec(128, iv));
        cipher.updateAAD(associatedData);
        return cipher.doFinal(plainText);
    }

    public static byte[] aesGcmDecrypt(SecretKey key, byte[] iv, byte[] cipherText, byte[] associatedData) throws GeneralSecurityException {
        Cipher cipher = Cipher.getInstance(AES_GCM_ALGO);
        cipher.init(Cipher.DECRYPT_MODE, key, new GCMParameterSpec(128, iv));
        cipher.updateAAD(associatedData);
        return cipher.doFinal(cipherText);
    }

    public static String hexString(byte[] bytes) {
        return HexFormat.of().formatHex(bytes);
    }

    public static byte[] fromHex(String hexString) {
        return HexFormat.of().parseHex(hexString);
    }

    public static KeyPair generateKeyPair() throws NoSuchAlgorithmException {
        KeyPairGenerator generator = KeyPairGenerator.getInstance(RSA_ALGO);
        generator.initialize(RSA_SIZE);
        return generator.generateKeyPair();
    }

    public static PublicKey readPublicKey(byte[] bytes) throws GeneralSecurityException {
        KeyFactory keyFactory = KeyFactory.getInstance(RSA_ALGO);
        EncodedKeySpec spec = new X509EncodedKeySpec(bytes);
        return keyFactory.generatePublic(spec);
    }

    public static PrivateKey readPrivateKey(byte[] bytes) throws GeneralSecurityException {
        KeyFactory keyFactory = KeyFactory.getInstance(RSA_ALGO);
        EncodedKeySpec spec = new PKCS8EncodedKeySpec(bytes);
        return keyFactory.generatePrivate(spec);
    }

    public static byte[] signWithRsa(PrivateKey privateKey, byte[] message) throws GeneralSecurityException {
        Cipher cipher = Cipher.getInstance(RSA_ALGO);
        cipher.init(Cipher.ENCRYPT_MODE, privateKey);
        return cipher.doFinal(message);
    }

    public static boolean verifyWithRsa(PublicKey publicKey, byte[] expectedMessage, byte[] signature) throws GeneralSecurityException {
        Cipher cipher = Cipher.getInstance(RSA_ALGO);
        cipher.init(Cipher.DECRYPT_MODE, publicKey);
        byte[] foundMessage = cipher.doFinal(signature);
        return Arrays.equals(foundMessage, expectedMessage);
    }
}
