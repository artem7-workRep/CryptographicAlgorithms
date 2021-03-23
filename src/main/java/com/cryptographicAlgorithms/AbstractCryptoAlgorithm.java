package main.java.com.cryptographicAlgorithms;

import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.io.Writer;

public class AbstractCryptoAlgorithm {
    EncryptDecryptBehavior encryptDecryptBehavior;

    public void setEncryptDecryptBehavior(EncryptDecryptBehavior encryptDecryptBehavior) {
        this.encryptDecryptBehavior = encryptDecryptBehavior;
    }

    public String encryptMessage(String message) {
        return encryptDecryptBehavior.encrypt(message);
    }

    public String decryptMessage(String message) {
        return encryptDecryptBehavior.decrypt(message);
    }

    public void writeInFile(String encryptData, File file) throws IOException {
        FileWriter fw = new FileWriter(file);
        String a = writeByte(encryptData);
        fw.write(a);
        fw.flush();
    }

    private String writeByte(String encryptMessage) {
        StringBuilder result = new StringBuilder();

        String[] stringEncryptArray = encryptMessage.split(" ");
        for(int i = 0; i < stringEncryptArray.length; i = i + 2) {
            long bytesOfString1 = Long.parseLong(stringEncryptArray[i], 16);
            long bytesOfString2 = Long.parseLong(stringEncryptArray[i + 1], 16);
            result.append(longToByte(bytesOfString1));
            result.append(longToByte(bytesOfString2));
            result.append("\n");
        }

        return result.toString();
    }

    private String longToByte(long number) {
        StringBuilder result = new StringBuilder();

        long copyNumber = number;
        for (int i = 0; i < 8; i++) {
            long temp = copyNumber & 0xFF;
            if (temp != 0) {
                result.append(Long.toHexString(temp) + " ");
            }else {
                result.append("0 ");
            }
            copyNumber = copyNumber >> 8;
        }
        StringBuilder res = new StringBuilder();
        String[] a = result.toString().split(" ");
        for (int i = a.length - 1; i >= 0; i--) {
            res.append(a[i] + " ");
        }
        return res.toString();
    }
}
