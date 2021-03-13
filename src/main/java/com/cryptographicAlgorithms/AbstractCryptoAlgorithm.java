package main.java.com.cryptographicAlgorithms;

public abstract class AbstractCryptoAlgorithm implements EncryptDecryptBehavior {
    EncryptDecryptBehavior encryptDecryptBehavior;

    public void setEncryptDecryptBehavior(EncryptDecryptBehavior encryptDecryptBehavior) {
        this.encryptDecryptBehavior = encryptDecryptBehavior;
    }

    /**
     *
     * @param text  Принимает обычную строку
     * @return      Байтовый массив длина которого кратна 8
     */
    protected byte[] StringToNecessaryByteArray(String text) {
        byte[] result = new byte[text.length()];
        if ((text.length() % 8) == 0) {
            result = new byte[text.length()];
        }

        if ((text.length() % 8) != 0) {
            int validSizeArray = text.length();
            while ((validSizeArray % 8) != 0) {
                validSizeArray++;
            }
            result = new byte[validSizeArray];
        }

        byte[] temp = text.getBytes();
        System.arraycopy(temp, 0, result, 0, temp.length);
        return result;
    }


    protected long dataInLongOfByteArray(byte[] data, int begin, int end) {
        StringBuilder result = new StringBuilder();

        for (int i = begin; i < end; i++) {
            String elementOfArrayInBinary =
                    String.format("%8s", Integer.toBinaryString(data[i])).replace(' ','0');
            result.append(elementOfArrayInBinary);
        }
        long res = Integer.parseInt(result.toString(), 2);
        return res;
    }

}
