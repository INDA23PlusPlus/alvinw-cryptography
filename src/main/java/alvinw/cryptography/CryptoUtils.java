package alvinw.cryptography;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import java.security.spec.KeySpec;

public class CryptoUtils {
    public static final String AES_GCM_ALGO = "AES/GCM/NoPadding";
    public static final String AES_ALGO = "AES";

    public static byte[] randomBytes(int length) {
        byte[] nonce = new byte[length];
        new SecureRandom().nextBytes(nonce);
        return nonce;
    }

    public static SecretKey deriveAesKeyFromPasswordAndNonce(String password, byte[] nonce) throws GeneralSecurityException {
        SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256"); // wtf is this
        KeySpec spec = new PBEKeySpec(password.toCharArray(), nonce, 65536, 256);
        return new SecretKeySpec(factory.generateSecret(spec).getEncoded(), "AES");
    }

    public static byte[] aesGcmEncrypt(SecretKey key, byte[] iv, byte[] plainText) throws GeneralSecurityException {
        Cipher cipher = Cipher.getInstance(AES_GCM_ALGO);
        cipher.init(Cipher.ENCRYPT_MODE, key, new GCMParameterSpec(128, iv));
        return cipher.doFinal(plainText);
    }

    public static byte[] aesGcmDecrypt(SecretKey key, byte[] iv, byte[] cipherText) throws GeneralSecurityException {
        Cipher cipher = Cipher.getInstance(AES_GCM_ALGO);
        cipher.init(Cipher.DECRYPT_MODE, key, new GCMParameterSpec(128, iv));
        return cipher.doFinal(cipherText);
    }
}
