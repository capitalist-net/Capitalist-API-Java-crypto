package net.capitalist;

import java.math.BigInteger;
import java.nio.charset.Charset;
import java.security.*;
import java.security.spec.*;
import javax.crypto.*;

public class PasswordEncoder {

    private static byte[] encryptData(byte[] content, Key key, String transformation) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        Cipher ciph = Cipher.getInstance(transformation);
        ciph.init(1, key);
        return ciph.doFinal(content);
    }

    private static String encryptData(String content, Key key, String transformation, Charset charset) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        return byteArrayToHexString(encryptData(content.getBytes(charset), key, transformation));
    }

    private static String encryptData(String content, Key key, String transformation) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        return encryptData(content, key, transformation, Charset.forName("UTF-8"));    }


    public static String encryptPassword(String password, String exponent, String modulus) {
        KeyFactory fact;

        try {
            fact = KeyFactory.getInstance("RSA");
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }

        RSAPublicKeySpec pub = new RSAPublicKeySpec(new BigInteger(modulus, 16), new BigInteger(exponent, 16));
        PublicKey publicKey;

        try {
            publicKey = fact.generatePublic(pub);
            return encryptData(password, publicKey, "RSA/ECB/PKCS1Padding");
        } catch (Exception e) {
            throw new IllegalArgumentException(e);
        }

    }

    private static String byteArrayToHexString(byte[] bytes) {
        char[] hexArray = new char[]{'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'A', 'B', 'C', 'D', 'E', 'F'};
        char[] hexChars = new char[bytes.length * 2];

        for(int j = 0; j < bytes.length; ++j) {
            int v = bytes[j] & 255;
            hexChars[j * 2] = hexArray[v >>> 4];
            hexChars[j * 2 + 1] = hexArray[v & 15];
        }

        return new String(hexChars);
    }
}
