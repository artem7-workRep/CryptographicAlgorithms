package main.java.com.cryptographicAlgorithms;

public class FunctionsForCryptographicAlgorithms {

    /**
     *
     * @param text          Принимает обычную строку
     * @param sizeOfBlock   Длина блока данных
     * @return              Байтовый массив длина которого кратна 8
     */
    public static byte[] stringToNecessaryByteArray(String text, int sizeOfBlock) {
        byte[] result = new byte[text.length()];

        if ((text.length() % sizeOfBlock) == 0) {
            result = new byte[text.length()];
        }
        if ((text.length() % sizeOfBlock) != 0) {
            int validSizeArray = text.length();
            while ((validSizeArray % sizeOfBlock) != 0) {
                validSizeArray++;
            }
            result = new byte[validSizeArray];
        }
        byte[] temp = text.getBytes();
        System.arraycopy(temp, 0, result, 0, temp.length);

        return result;
    }


    public static long dataInLongOfByteArray(byte[] data, int begin, int end) {
        StringBuilder result = new StringBuilder();

        for (int i = begin; i < end; i++) {
            String elementOfArrayInBinary =
                    String.format("%8s", Integer.toBinaryString(data[i])).replace(' ','0');
            result.append(elementOfArrayInBinary);
        }

        return Integer.parseInt(result.toString(), 2);
    }

}
