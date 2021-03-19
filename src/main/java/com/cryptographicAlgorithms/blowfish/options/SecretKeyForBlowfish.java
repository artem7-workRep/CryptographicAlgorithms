package main.java.com.cryptographicAlgorithms.blowfish.options;
import main.java.com.cryptographicAlgorithms.blowfish.AdditionKeys;

public class SecretKeyForBlowfish implements AdditionKeys {
    private final String KeyStr;
    private final char[] keyInChar;

    public SecretKeyForBlowfish(String key) {
        KeyStr = necessaryKeyLength(key);
        keyInChar = KeyStr.toCharArray();
    }

    public String getKeyStr() {
        return KeyStr;
    }

    private String necessaryKeyLength(String key) {
        String result = null;
        StringBuilder builder = new StringBuilder(key);

        if (key.length() < 36) {
            while (builder.length() < 36) {
                builder.append(key);
            }
            result = builder.toString().substring(0, 36);
            return result;
        }else if (builder.length() >= 36) {
            result = builder.substring(0, 36);
        }

        System.out.println("Result = " + result);
        return result;
    }

    @Override
    public char[] keyToCharArray() {
        return keyInChar;
    }


}
