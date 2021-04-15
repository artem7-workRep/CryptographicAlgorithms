package main.java.com.cryptographicAlgorithms.blowfish.options;

import main.java.com.cryptographicAlgorithms.AdditionKeys;

import java.util.Arrays;

public class SecretKeyForBlowfish implements AdditionKeys {
    private final byte[] keyInByteArray;

    public SecretKeyForBlowfish(String key) {
        keyInByteArray = necessaryKeyLength(key).getBytes();
    }

    public String necessaryKeyLength(String key) {
        String result = null;
        StringBuilder builder = new StringBuilder(key);

        if (key.length() < 72) {
            while (builder.length() < 72) {
                builder.append(key);
            }
            result = builder.substring(0, 72);
            return result;
        }else if (builder.length() >= 72) {
            result = builder.substring(0, 72);
        }
        return result;
    }

    @Override
    public byte[] keyInByteArray() {
        return keyInByteArray;
    }
}
