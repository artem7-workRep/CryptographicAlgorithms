package main.java.com.cryptographicAlgorithms.blowfish;

import main.java.com.cryptographicAlgorithms.AbstractCryptoAlgorithm;
import main.java.com.cryptographicAlgorithms.blowfish.options.SPbox;
import main.java.com.cryptographicAlgorithms.blowfish.options.SecretKey;

import java.util.ArrayList;
import java.util.Base64;
import java.util.Collections;

public class Blowfish extends AbstractCryptoAlgorithm {
    private SecretKey secretKey;
    private SPbox sp;


    public Blowfish(SecretKey secretKey) {
        this.secretKey = secretKey;
        sp = new SPbox(secretKey);
        sp.initKey();
    }

    /**
     *
     * @param OpenText  Открытый текст, который необходимо зашифровать
     * @return          Зашифрованный текст
     */
    public String encrypt(String OpenText) {
        StringBuilder result  = new StringBuilder();
        String encodeOpenText = Base64.getEncoder().encodeToString(OpenText.getBytes());
        byte[] openDataInByte = StringToNecessaryByteArray(encodeOpenText);

        for (int i = 0; i < openDataInByte.length; i += 8) {
            long left = dataInLongOfByteArray(openDataInByte, i, i + 4);
            long right = dataInLongOfByteArray(openDataInByte, i + 4, i + 8);

            String[] encryptBlock = functionEnc(left, right, sp);
            result.append(Long.toHexString(Long.parseLong(encryptBlock[0])) + " "
                    + Long.toHexString(Long.parseLong(encryptBlock[1])) + " ");
        }

        return result.toString();
    }

    /**
     *
     * @param EncryptText   Закрытый текст
     * @return              Открытый текст
     */
    public String decrypt(String EncryptText) {
        String result;
        var decryptDataInBase64 = new StringBuilder();
        var decryptByte         = new ArrayList<Long>();

        String[] dataForDecrypt = EncryptText.split(" ");
        for (int i = 0; i < dataForDecrypt.length; i += 2) {
            long left = Long.parseLong(dataForDecrypt[i], 16);
            long right = Long.parseLong(dataForDecrypt[i + 1], 16);
            String[] decryptText = functionDec(left, right, sp);
            decryptByte.addAll(BytesOfData(Long.parseLong(decryptText[0]), Long.parseLong(decryptText[1])));
        }
        for (long temp : decryptByte) {
            if (temp != 0) {
                decryptDataInBase64.append((char) temp);
            }
        }
        result = new String(Base64.getDecoder().decode(decryptDataInBase64.toString().getBytes()));
        return result;
    }


    private String[] functionEnc(long dataLeft_32, long dataRight_32, SPbox sp) {
        //left and right encrypt block
        String[] result = new String[2];

        long left = dataLeft_32;
        long right = dataRight_32;

        for (int i = 0; i < 16; i++) {
            left = left ^ sp.getChangedPArray()[i];
            right = methodF(left, sp) ^ right;
            left = left + right;
            right = left - right;
            left = left - right;
        }
        left = left + right;
        right = left - right;
        left = left - right;

        right = right ^ sp.getChangedPArray()[16];
        left = left ^ sp.getChangedPArray()[17];
        result[0] = String.valueOf(left);
        result[1] = String.valueOf(right);

        return result;
    }

    private String[] functionDec(long dataLeft_32, long dataRight_32, SPbox sp) {
        String[] result = new String[2];

        long left = dataLeft_32;
        long right = dataRight_32;

        for (int i = 17; i > 1; i--) {
            left = left ^ sp.getChangedPArray()[i];
            right = methodF(left, sp) ^ right;
            left = left + right;
            right = left - right;
            left = left - right;
        }
        left = left + right;
        right = left - right;
        left = left - right;
        right = right ^ sp.getChangedPArray()[1];
        left = left ^ sp.getChangedPArray()[0];

        result[0] = String.valueOf(left);
        result[1] = String.valueOf(right);
        return result;
    }

    private long methodF(long data, SPbox sp) {
        long result;
        long copyData = data;

        long x4 = copyData & 0xFF;
        copyData = copyData >> 8;

        long x3 = copyData & 0xFF;
        copyData = copyData >> 8;

        long x2 = copyData & 0xFF;
        copyData = copyData >> 8;

        long x1 = copyData & 0xFF;

        result = sp.getChangedSBox0()[(int)x1] + sp.getChangedSBox1()[(int)x1];
        result = result ^ sp.getChangedSBox2()[(int)x1];
        result = result + sp.getChangedSBox3()[(int)x1];
        return result;
    }

    private ArrayList<Long> BytesOfData(long left, long right) {
        var result = new ArrayList<Long>();
        var temp1 = new ArrayList<Long>();

        for (int i = 0; i < 4; i++) {
            temp1.add(right & 0xFF);
            right = right >> 8;
        }

        for (int i = 0; i < 4; i++) {
            temp1.add(left & 0xFF);
            left = left >> 8;
        }

        Collections.reverse(temp1);
        result.addAll(temp1);
        return result;
    }

}
