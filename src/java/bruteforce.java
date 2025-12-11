import java.util.*;
import java.nio.file.*;
import java.io.IOException;

/**
 * Rail Fence Cipher Brute Force Attack
 * Uses local wordlist files for offline dictionary validation
 */
public class bruteforce {
    
    // Configuration: All wordlist files loaded for comprehensive dictionary coverage
    private static final String[] WORDLIST_PATHS = {
        "assets/all_words.txt",
        "assets/words.txt",
        "assets/dwyl.txt",
        "assets/nouns.txt",
        "assets/verbs.txt",
        "assets/adjs.txt",
        "assets/advs.txt",
        "assets/adps.txt",
        "assets/conjs.txt",
        "assets/dets.txt",
        "assets/nums.txt",
        "assets/prons.txt",
        "assets/prts.txt"
    };
    
    // Common words get higher weight in scoring
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
        COMMON_WORD_WEIGHT.put("is", 4);
        COMMON_WORD_WEIGHT.put("was", 4);
        COMMON_WORD_WEIGHT.put("have", 4);
    }
    
    // Cache for loaded wordlists
    private static Set<String> wordSet = null;
    
    /**
     * Loads all wordlist files and combines them into a single Set
     * @return Set of all words from all wordlists
     */
    private static Set<String> loadWordSets() {
        if (wordSet != null) return wordSet;
        
        wordSet = new HashSet<>();
        
        for (String path : WORDLIST_PATHS) {
            try {
                if (!Files.exists(Paths.get(path))) {
                    System.err.println("Warning: Wordlist not found: " + path);
                    continue;
                }
                
                List<String> lines = Files.readAllLines(Paths.get(path));
                for (String line : lines) {
                    String word = line.trim().toLowerCase();
                    if (word.length() >= 3) {
                        wordSet.add(word);
                    }
                }
            } catch (IOException e) {
                System.err.println("Error loading wordlist " + path + ": " + e.getMessage());
            }
        }
        
        System.out.println("Loaded " + wordSet.size() + " words from " + WORDLIST_PATHS.length + " wordlist(s)");
        return wordSet;
    }
    
    /**
     * Checks if a word exists in the loaded wordlists
     * @param word Word to check (will be lowercased)
     * @return True if word exists in wordlists
     */
    private static boolean isWordInDictionary(String word) {
        if (word == null || word.length() < 3) return false;
        Set<String> words = loadWordSets();
        return words.contains(word.toLowerCase());
    }
    
    /**
     * Decrypts ciphertext using the Rail Fence Cipher
     * @param ciphertext The encrypted message
     * @param rails Number of rails used for encryption
     * @return The decrypted plaintext
     */
    public static String decrypt(String ciphertext, int rails) {
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
    
    /**
     * Extracts token words from text (space-separated)
     * @param text Input text
     * @return List of words (length >= 3)
     */
    private static List<String> extractWords(String text) {
        List<String> words = new ArrayList<>();
        String[] tokens = text.toLowerCase().replaceAll("[^a-z\\s]", " ").split("\\s+");
        for (String token : tokens) {
            if (token.length() >= 3) {
                words.add(token);
            }
        }
        return words;
    }
    
    /**
     * Extracts substrings from words to catch concatenated words
     * @param words List of words
     * @param maxCount Maximum number of substrings to extract
     * @return List of substrings (length 3-8)
     */
    private static List<String> extractSubstrings(List<String> words, int maxCount) {
        List<String> substrings = new ArrayList<>();
        
        for (String word : words) {
            int maxLen = Math.min(8, word.length());
            for (int len = maxLen; len >= 3; len--) {
                for (int i = 0; i <= word.length() - len; i++) {
                    substrings.add(word.substring(i, i + len));
                    if (substrings.size() >= maxCount) return substrings;
                }
            }
        }
        
        return substrings;
    }
    
    /**
     * Scores plaintext based on dictionary word matches
     * @param text Plaintext to score
     * @return Score (higher = more likely correct)
     */
    public static double calculateReadabilityScore(String text) {
        if (text == null || text.isEmpty()) {
            return 0.0;
        }
        
        loadWordSets();
        
        List<String> words = extractWords(text);
        List<String> substrings = extractSubstrings(words, 15);
        
        int totalHits = 0;
        int weightedScore = 0;
        int checked = 0;
        final int maxChecks = 30;
        
        // Check full words first (stronger signal)
        for (String word : words) {
            if (checked >= maxChecks) break;
            
            if (isWordInDictionary(word)) {
                totalHits++;
                int weight = COMMON_WORD_WEIGHT.getOrDefault(word, 1);
                weightedScore += weight * Math.max(word.length(), 3);
            }
            checked++;
        }
        
        // Check substrings to catch concatenated words
        for (String substr : substrings) {
            if (checked >= maxChecks) break;
            
            if (isWordInDictionary(substr)) {
                totalHits++;
                int weight = COMMON_WORD_WEIGHT.getOrDefault(substr, 1);
                weightedScore += weight * Math.max(substr.length(), 3);
            }
            checked++;
        }
        
        // Calculate additional scoring factors
        int spacingCount = 0;
        for (char c : text.toCharArray()) {
            if (c == ' ') spacingCount++;
        }
        
        double coverageScore = checked > 0 ? ((double) totalHits / checked) * 5.0 : 0.0;
        double spacingScore = spacingCount * 0.2;
        double zeroPenalty = totalHits == 0 ? -10.0 : 0.0;
        
        return weightedScore + coverageScore + spacingScore + zeroPenalty;
    }
    
    /**
     * Performs a brute force attack on the ciphertext by trying all possible keys
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
     * Helper class to store decryption results
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
     * Main method to run the brute force program
     */
    public static void main(String[] args) {
        Scanner scanner = new Scanner(System.in);
        
        System.out.println("==================================================");
        System.out.println("   RAIL FENCE CIPHER - BRUTE FORCE (Offline)");
        System.out.println("==================================================");
        System.out.println("\nUses local wordlist files to pick the most likely rails.");
        System.out.println();
        
        // Pre-load wordlists
        loadWordSets();
        
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
