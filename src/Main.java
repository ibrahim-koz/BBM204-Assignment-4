import java.io.*;
import java.util.*;

import static java.lang.Integer.max;
import static java.lang.Integer.min;

public class Main{

    public static void main(String[] args) throws Exception {
        TST<Value> tst = new TST();
        String[] prefixes = {"https://www.", "http://www.", "https://", "http://"};

        // Legitimate

        BufferedReader reader = new BufferedReader(new FileReader("legitimatetrain.txt"));

        final int nGramLength = 4;

        HashMap<String, Value> ngHM = new HashMap<>();

        HashMap<String, Value> legitimateHM = new HashMap<>();
        NGrams ng = new NGrams();
        final int ltTrainingNum = readnGrams(ng, prefixes, reader, nGramLength);
        for (String s : ng.getnGrams()) {
            if (legitimateHM.containsKey(s)) {
                tst.get(s).increaseLO();
            } else {
                tst.put(s, new Value('l'));
                ngHM.put(s, tst.get(s));
                legitimateHM.put(s, tst.get(s));
            }

        }
        reader.close();

        Map.Entry<String, Value>[] legitimateArray = legitimateHM.entrySet().toArray(new Map.Entry[]{});
        Arrays.sort(legitimateArray, (o1, o2) -> o2.getValue().legitimateOccurrence - o1.getValue().legitimateOccurrence);


        // Phishing
        reader = new BufferedReader(new FileReader("phishingtrain.txt"));

        HashMap<String, Value> phishingHM = new HashMap<>();
        ng = new NGrams();
        final int phTrainingNum = readnGrams(ng, prefixes, reader, nGramLength);

        for (String s : ng.getnGrams()) {
            if (phishingHM.containsKey(s)) {
                tst.get(s).increasePO();
            } else {
                if (!tst.contains(s)) {
                    tst.put(s, new Value('p'));
                    ngHM.put(s, tst.get(s));
                } else
                    tst.get(s).increasePO();
                phishingHM.put(s, tst.get(s));
            }
        }

        reader.close();

        Map.Entry<String, Value>[] phishingArray = phishingHM.entrySet().toArray(new Map.Entry[]{});
        Arrays.sort(phishingArray, (o1, o2) -> o2.getValue().phishOccurrence - o1.getValue().phishOccurrence);


        final int featureSize = 5000;

        BufferedWriter writer = new BufferedWriter(new FileWriter("strong_legitimate_features.txt"));
        writer.write("Most important legitimate n_grams\n");


        for (int i = 0; i < featureSize; i++) {
            writer.write(String.format("%d. %s - freq: %d\n", i + 1, legitimateArray[i].getKey(), legitimateArray[i].getValue().legitimateOccurrence));
        }

        writer.close();


        writer = new BufferedWriter(new FileWriter("strong_phishing_features.txt"));
        writer.write("Most important phishing n_grams\n");


        for (int i = 0; i < featureSize; i++) {
            writer.write(String.format("%d. %s - freq: %d\n", i + 1, phishingArray[i].getKey(), phishingArray[i].getValue().phishOccurrence));
        }

        writer.close();

        writer = new BufferedWriter(new FileWriter("all_feature_weights.txt"));


        Map.Entry<String, Value>[] ngArray = ngHM.entrySet().toArray(new Map.Entry[]{});
        for (Map.Entry<String, Value> e : ngArray)
            e.getValue().computeWeight();

        Arrays.sort(ngArray, (o1, o2) -> {
            if (o2.getValue().weight - o1.getValue().weight > 0)
                return 1;
            else if (o2.getValue().weight - o1.getValue().weight < 0)
                return -1;
            else
                return 0;
        });

        for (Map.Entry<String, Value> e : ngArray) {
            writer.write(String.format("%s - weight: %f\n", e.getKey(), e.getValue().weight));
        }

        writer.close();

        HashMap<String, Value> bestValues = new HashMap<>();
        for (int i = 0; i < featureSize; i++) {
            bestValues.put(legitimateArray[i].getKey(), legitimateArray[i].getValue());
            bestValues.put(phishingArray[i].getKey(), phishingArray[i].getValue());
        }
        for (String key : ngHM.keySet()) {
            if (!bestValues.containsKey(key)) {
                tst.put(key, null);
            }
        }

        int[] values = new int[6]; // values[0] TP, values[1] FN, values[2] TN, values[3] FP,
        // values[4] UP, values[5] UL


        reader = new BufferedReader(new FileReader("legitimatetest.txt"));
        final int ltTestNum = readURL(prefixes, reader, nGramLength, tst, values, 'l');
        reader.close();

        reader = new BufferedReader(new FileReader("phishingtest.txt"));
        final int phTestNum = readURL(prefixes, reader, nGramLength, tst, values, 'p');
        reader.close();

        int numerator = 0;
        for (int i : values)
            numerator += i;

        double accuracy = (float) (values[0] + values[2]) / numerator;


        System.out.println("n-gram based phishing detection via TST ");
        System.out.println("feat_size: " + featureSize);
        System.out.println("n_gram_size: " + nGramLength);
        System.out.println(String.format("Legitimate training file has been loaded with [%d] instances", ltTrainingNum));
        System.out.println(String.format("Legitimate test file has been loaded with [%d] instances", ltTestNum));
        System.out.println(String.format("Phishing training file has been loaded with [%d] instances", phTrainingNum));
        System.out.println(String.format("Phishing test file has been loaded with [%d] instances", phTestNum));
        System.out.println("TST has been loaded with 3000 n-grams");
        System.out.println("TST has been loaded with 3000 n-grams");
        System.out.println(featureSize + " strong phishing n-grams have been saved to the file\"strong_phishing_features.txt\"");
        System.out.println(featureSize + " strong legitimate n-grams have been saved to the file\"strong_phishing_features.txt\"");
        System.out.println(ngArray.length + " n-grams + weights have been saved to the file \"all_feature_weights.txt\"");
        System.out.println(ngArray.length - tst.size() + " insignificant n-grams have been removed from the TST");
        System.out.println(String.format("TP:%d FN:%d TN:%d FP:%d Unpredictable Phishing:%d Unpredictable Legitimate:%d "
                ,values[0], values[1], values[2], values[3], values[4], values[5]));
        System.out.println("Accuracy: " + accuracy);

    }

    private static int readnGrams(NGrams ng, String[] prefixes, BufferedReader reader, int nGramNumber) throws IOException {
        String line;
        int lineNumber = 0;
        while ((line = reader.readLine()) != null) {
            line = line.toLowerCase();
            for (String prefix : prefixes)
                if (line.startsWith(prefix)) {
                    line = line.substring(prefix.length());
                    break;
                }
            ng.generateNGrams(line, nGramNumber);
            lineNumber += 1;
        }
        return lineNumber;
    }

    private static int readURL(String[] prefixes, BufferedReader reader, int nGramNumber, TST<Value> tst,
                                int[] values, char c) throws IOException {
        String line;
        int lineNumber = 0;
        while ((line = reader.readLine()) != null) {
            line = line.toLowerCase();
            NGrams ng = new NGrams();
            lineNumber += 1;
            for (String prefix : prefixes)
                if (line.startsWith(prefix)) {
                    line = line.substring(prefix.length());
                    break;
                }
            ng.generateNGrams(line, nGramNumber);
            double total_score = 0;
            for (String nGram : ng.getnGrams())
                if (tst.contains(nGram))
                    total_score += tst.get(nGram).weight;
            if (c == 'l') {
                if (total_score > 0)
                    values[3] += 1;
                else if (total_score < 0)
                    values[2] += 1;
                else
                    values[5] += 1;

            } else if (c == 'p') {
                if (total_score > 0)
                    values[0] += 1;
                else if (total_score < 0)
                    values[1] += 1;
                else
                    values[4] += 1;
            }
        }
        return lineNumber;
    }
}


class NGrams {
    ArrayList<String> nGrams = new ArrayList<>();

    public void generateNGrams(String str, int n) {
        int currentIndex = 0;
        while ((str.length() - 1) - currentIndex + 1 >= n) {
            nGrams.add(str.substring(currentIndex, currentIndex + n));
            currentIndex += 1;
        }
    }

    public ArrayList<String> getnGrams() {
        return nGrams;
    }
}

class Value {
    int phishOccurrence;
    int legitimateOccurrence;
    double weight;

    public Value(char c) {
        if (c == 'p') {
            phishOccurrence = 1;
            legitimateOccurrence = 0;
        } else if (c == 'l') {
            phishOccurrence = 0;
            legitimateOccurrence = 1;
        }
    }

    public void increasePO() {
        phishOccurrence += 1;
    }

    public void increaseLO() {
        legitimateOccurrence += 1;
    }

    public void computeWeight() {
        if (phishOccurrence > 0 && legitimateOccurrence == 0)
            weight = 1;
        else if (phishOccurrence == 0 && legitimateOccurrence > 0)
            weight = -1;
        else if (phishOccurrence > 0 && legitimateOccurrence > 0) {
            if (phishOccurrence > legitimateOccurrence)
                weight = (float) min(phishOccurrence, legitimateOccurrence) / max(phishOccurrence, legitimateOccurrence);
            else if (phishOccurrence < legitimateOccurrence)
                weight = (float) -min(phishOccurrence, legitimateOccurrence) / max(phishOccurrence, legitimateOccurrence);
            else
                weight = 0;
        }
    }

}
