import java.util.Scanner;
import java.util.ArrayList;
import java.util.List;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import java.util.ArrayList;
import java.net.HttpURLConnection;
import java.net.URL;

public class bruteforce {
    
    /**
     * Decrypts ciphertext using the Rail Fence Cipher.
     * (Same implementation as in RailFenceCipher.java)
     * 
     * @param ciphertext The encrypted message
     * @param rails Number of rails used for encryption
     * @return The decrypted plaintext
     */
    public static String decrypt(String ciphertext, int rails) {
        // Handle edge cases
        if (rails <= 1 || rails >= ciphertext.length()) {
            return ciphertext;
        }
        
        // Build pattern of rail indices for each character
        int[] pattern = new int[ciphertext.length()];
        int rail = 0;
        int direction = 1;
        for (int i = 0; i < ciphertext.length(); i++) {
            pattern[i] = rail;
            if (rail == 0) direction = 1;
            else if (rail == rails - 1) direction = -1;
            rail += direction;
        }
        
        // Count characters per rail
        int[] railCounts = new int[rails];
        for (int r : pattern) {
            railCounts[r]++;
        }
        
        // Slice ciphertext into buckets per rail
        char[][] buckets = new char[rails][];
        int idx = 0;
        for (int r = 0; r < rails; r++) {
            buckets[r] = ciphertext.substring(idx, idx + railCounts[r]).toCharArray();
            idx += railCounts[r];
        }
        
        // Reconstruct plaintext following the pattern
        StringBuilder plaintext = new StringBuilder();
        int[] bucketPos = new int[rails];
        rail = 0;
        direction = 1;
        for (int i = 0; i < ciphertext.length(); i++) {
            plaintext.append(buckets[rail][bucketPos[rail]++]);
            if (rail == 0) direction = 1;
            else if (rail == rails - 1) direction = -1;
            rail += direction;
        }
        
        return plaintext.toString();
    }
    
    private static final Map<String, Boolean> dictionaryCache = new HashMap<>();
    private static final Map<String, Integer> COMMON_WORD_WEIGHT = new HashMap<>();
    static {
        COMMON_WORD_WEIGHT.put("the", 6);
        COMMON_WORD_WEIGHT.put("and", 6);
        COMMON_WORD_WEIGHT.put("for", 5);
        COMMON_WORD_WEIGHT.put("are", 5);
        COMMON_WORD_WEIGHT.put("you", 5);
        COMMON_WORD_WEIGHT.put("this", 5);
        COMMON_WORD_WEIGHT.put("that", 5);
        COMMON_WORD_WEIGHT.put("with", 5);
        COMMON_WORD_WEIGHT.put("meet", 5);
        COMMON_WORD_WEIGHT.put("hello", 6);
        COMMON_WORD_WEIGHT.put("hi", 3);
        COMMON_WORD_WEIGHT.put("world", 5);
    }
    
    /**
     * Check dictionary API for a word. Cached to reduce calls.
     */
    public static boolean isRealWord(String word) {
        if (word == null || word.length() < 3) return false;
        if (dictionaryCache.containsKey(word)) return dictionaryCache.get(word);
        
        try {
            String urlStr = "https://api.dictionaryapi.dev/api/v2/entries/en/" + word;
            URL url = new URL(urlStr);
            HttpURLConnection conn = (HttpURLConnection) url.openConnection();
            conn.setRequestMethod("GET");
            conn.setConnectTimeout(2000);
            conn.setReadTimeout(2000);
            
            boolean ok = conn.getResponseCode() == 200;
            dictionaryCache.put(word, ok);
            return ok;
        } catch (Exception e) {
            dictionaryCache.put(word, false);
            return false;
        }
    }
    
    private static List<String> collectTokenWords(String text) {
        List<String> tokens = new ArrayList<>();
        String[] cleanWords = text.toLowerCase().replaceAll("[^a-z\\s]", " ").split("\\s+");
        for (String w : cleanWords) {
            if (w.length() >= 3) tokens.add(w);
        }
        return tokens;
    }
    
    private static List<String> collectSubstrings(List<String> words, int cap) {
        List<String> result = new ArrayList<>();
        for (String word : words) {
            int maxLen = Math.min(8, word.length());
            for (int len = maxLen; len >= 3; len--) {
                for (int i = 0; i <= word.length() - len; i++) {
                    result.add(word.substring(i, i + len));
                    if (result.size() >= cap) return result;
                }
            }
        }
        return result;
    }
    
    /**
     * Dictionary-based score aligned with the web version.
     */
    public static double calculateReadabilityScore(String text) {
        if (text == null || text.isEmpty()) {
            return 0.0;
        }
        
        List<String> tokens = collectTokenWords(text);
        List<String> candidates = collectSubstrings(tokens, 15);
        int hits = 0;
        int checked = 0;
        int weighted = 0;
        
        // Check full tokens first
        for (String word : tokens) {
            if (checked >= 15) break;
            if (isRealWord(word)) {
                hits++;
                weighted += (COMMON_WORD_WEIGHT.getOrDefault(word, 1) * Math.max(word.length(), 3));
            }
            checked++;
        }
        
        // Then substrings to capture concatenated words
        for (String word : candidates) {
            if (checked >= 15) break;
            if (isRealWord(word)) {
                hits++;
                weighted += (COMMON_WORD_WEIGHT.getOrDefault(word, 1) * Math.max(word.length(), 3));
            }
            checked++;
        }
        
        int spacing = 0;
        for (char c : text.toCharArray()) {
            if (c == ' ') spacing++;
        }
        
        double coverage = checked > 0 ? (double) hits / checked : 0.0;
        double zeroPenalty = hits == 0 ? -10.0 : 0.0;
        return weighted + coverage * 5.0 + spacing * 0.2 + zeroPenalty;
    }
    
    /**
     * Performs a brute force attack on the ciphertext by trying all possible keys.
     * 
     * @param ciphertext The encrypted message to crack
     */
    public static void bruteForceAttack(String ciphertext) {
        if (ciphertext == null || ciphertext.length() < 2) {
            System.out.println("Ciphertext is too short for brute force attack.");
            return;
        }
        
        System.out.println("\n==================================================");
        System.out.println("         BRUTE FORCE ATTACK RESULTS");
        System.out.println("==================================================");
        System.out.println("Attempting all possible keys from 2 to " + (ciphertext.length() - 1));
        System.out.println();
        
        List<DecryptionResult> results = new ArrayList<>();
        
        // Try all possible rail values
        for (int rails = 2; rails < ciphertext.length(); rails++) {
            String decrypted = decrypt(ciphertext, rails);
            double score = calculateReadabilityScore(decrypted);
            results.add(new DecryptionResult(rails, decrypted, score));
        }
        
        // Find the best result
        DecryptionResult bestResult = results.get(0);
        for (DecryptionResult result : results) {
            if (result.score > bestResult.score) {
                bestResult = result;
            }
        }
        
        // Display all results
        for (DecryptionResult result : results) {
            boolean isBest = (result == bestResult);
            
            if (isBest) {
                System.out.println(">>> MOST LIKELY CORRECT <<<");
            }
            
            System.out.println("Rails: " + result.rails);
            System.out.println("Decrypted: " + result.plaintext);
            System.out.println("Readability Score: " + String.format("%.2f", result.score));
            
            if (isBest) {
                System.out.println(">>> MOST LIKELY CORRECT <<<");
            }
            
            System.out.println("--------------------------------------------------");
        }
        
        System.out.println("\nSUMMARY:");
        System.out.println("Total attempts: " + results.size());
        System.out.println("Best guess - Rails: " + bestResult.rails);
        System.out.println("Best guess - Message: " + bestResult.plaintext);
    }
    
    /**
     * Helper class to store decryption results.
     */
    static class DecryptionResult {
        int rails;
        String plaintext;
        double score;
        
        DecryptionResult(int rails, String plaintext, double score) {
            this.rails = rails;
            this.plaintext = plaintext;
            this.score = score;
        }
    }
    
    /**
     * Main method to run the brute force program.
     */
    public static void main(String[] args) {
        Scanner scanner = new Scanner(System.in);
        
        System.out.println("==================================================");
        System.out.println("   RAIL FENCE CIPHER - BRUTE FORCE (Dictionary)");
        System.out.println("==================================================");
        System.out.println("\nUses free dictionary API to pick the most likely rails.");
        System.out.println();
        
        boolean running = true;
        
        while (running) {
            System.out.print("Enter the ciphertext to crack: ");
            String ciphertext = scanner.nextLine().trim();
            
            if (ciphertext.isEmpty()) {
                System.out.println("Error: Ciphertext cannot be empty.");
                continue;
            }
            
            if (ciphertext.length() < 3) {
                System.out.println("Error: Ciphertext is too short (minimum 3 characters).");
                continue;
            }
            
            // Perform brute force attack
            bruteForceAttack(ciphertext);
            
            // Ask if user wants to try again
            System.out.print("\nWould you like to crack another message? (y/n): ");
            String response = scanner.nextLine().trim().toLowerCase();
            
            if (!response.equals("y") && !response.equals("yes")) {
                running = false;
                System.out.println("\nThank you for using the Brute Force Attack tool!");
            }
            
            System.out.println();
        }
        
        scanner.close();
    }
}