package main.java.com.cryptographicAlgorithms;

import main.java.com.cryptographicAlgorithms.blowfish.Blowfish;
import main.java.com.cryptographicAlgorithms.blowfish.options.SecretKeyForBlowfish;

public class MainMethod {
    public static void main(String[] args) {
        AbstractCryptoAlgorithm cryptoAlgorithm = new AbstractCryptoAlgorithm();
        cryptoAlgorithm.setEncryptDecryptBehavior(new Blowfish(
                new SecretKeyForBlowfish("abew2423+@#$+@#_$@@cdvw")));
        String data = "Hello World!";

        String encrypt = cryptoAlgorithm.encryptMessage(data);
        String decrypt = cryptoAlgorithm.decryptMessage(encrypt);

        System.out.println(data.equals(decrypt));
        System.out.println(encrypt);
        System.out.println(decrypt);



    }
}
