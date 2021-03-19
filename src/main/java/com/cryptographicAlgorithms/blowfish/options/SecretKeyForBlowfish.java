package main.java.com.cryptographicAlgorithms.blowfish.options;

import main.java.com.cryptographicAlgorithms.blowfish.AdditionKeys;

public class SecretKey implements AdditionKeys {
    private final String KeyStr;
    private final char[] keyInChar;

    public SecretKey(String key) {
        KeyStr = key;
        keyInChar = key.toCharArray();
    }

    public String getKeyStr() {
        return KeyStr;
    }


    @Override
    public char[] keyToCharArray() {
        return keyInChar;
    }
}
