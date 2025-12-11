import java.util.Scanner;

public class RailFenceCipher {
    
    /**
     * Encrypts plaintext using the Rail Fence Cipher.
     * 
     * @param plaintext The message to encrypt
     * @param rails Number of rails (rows) to use
     * @return The encrypted ciphertext
     */
    public static String encrypt(String plaintext, int rails) {
        // Handle edge cases
        if (rails <= 1 || rails >= plaintext.length()) {
            return plaintext;
        }
        
        // Create a 2D array to hold characters for each rail
        StringBuilder[] fence = new StringBuilder[rails];
        for (int i = 0; i < rails; i++) {
            fence[i] = new StringBuilder();
        }
        
        // Variables to track direction and current rail
        int rail = 0;
        int direction = 1;  // 1 means going down, -1 means going up
        
        // Place each character in the zigzag pattern
        for (int i = 0; i < plaintext.length(); i++) {
            fence[rail].append(plaintext.charAt(i));
            
            // Change direction at top and bottom rails
            if (rail == 0) {
                direction = 1;
            } else if (rail == rails - 1) {
                direction = -1;
            }
            
            rail += direction;
        }
        
        // Read characters row by row to create ciphertext
        StringBuilder ciphertext = new StringBuilder();
        for (int i = 0; i < rails; i++) {
            ciphertext.append(fence[i]);
        }
        
        return ciphertext.toString();
    }
    
    /**
     * Decrypts ciphertext using the Rail Fence Cipher.
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
        
        // Build pattern of rail indices for each position
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
        
        // Slice ciphertext into rail buckets
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
     * Main method to run the Rail Fence Cipher program.
     */
    public static void main(String[] args) {
        Scanner scanner = new Scanner(System.in);
        
        System.out.println("==================================================");
        System.out.println("           RAIL FENCE CIPHER");
        System.out.println("==================================================");
        
        boolean running = true;
        
        while (running) {
            System.out.println("\nChoose an option:");
            System.out.println("1. Encrypt a message");
            System.out.println("2. Decrypt a message");
            System.out.println("3. Exit");
            System.out.print("\nEnter your choice (1-3): ");
            
            String choice = scanner.nextLine().trim();
            
            switch (choice) {
                case "1":
                    // Encryption
                    System.out.print("\nEnter the plaintext to encrypt: ");
                    String plaintext = scanner.nextLine();
                    
                    int encryptRails = 0;
                    boolean validInput = false;
                    
                    while (!validInput) {
                        try {
                            System.out.print("Enter the number of rails (2 or more): ");
                            encryptRails = Integer.parseInt(scanner.nextLine());
                            
                            if (encryptRails < 2) {
                                System.out.println("Number of rails must be 2 or more.");
                            } else if (encryptRails >= plaintext.length()) {
                                System.out.println("Number of rails must be less than message length (" 
                                                   + plaintext.length() + ").");
                            } else {
                                validInput = true;
                            }
                        } catch (NumberFormatException e) {
                            System.out.println("Please enter a valid number.");
                        }
                    }
                    
                    String ciphertext = encrypt(plaintext, encryptRails);
                    System.out.println("\nEncrypted message: " + ciphertext);
                    break;
                
                case "2":
                    // Decryption
                    System.out.print("\nEnter the ciphertext to decrypt: ");
                    String ciphertextInput = scanner.nextLine();
                    
                    int decryptRails = 0;
                    validInput = false;
                    
                    while (!validInput) {
                        try {
                            System.out.print("Enter the number of rails used: ");
                            decryptRails = Integer.parseInt(scanner.nextLine());
                            
                            if (decryptRails < 2) {
                                System.out.println("Number of rails must be 2 or more.");
                            } else if (decryptRails >= ciphertextInput.length()) {
                                System.out.println("Number of rails must be less than message length (" 
                                                   + ciphertextInput.length() + ").");
                            } else {
                                validInput = true;
                            }
                        } catch (NumberFormatException e) {
                            System.out.println("Please enter a valid number.");
                        }
                    }
                    
                    String decryptedText = decrypt(ciphertextInput, decryptRails);
                    System.out.println("\nDecrypted message: " + decryptedText);
                    break;
                
                case "3":
                    System.out.println("\nThank you for using Rail Fence Cipher!");
                    running = false;
                    break;
                
                default:
                    System.out.println("\nInvalid choice. Please try again.");
            }
        }
        
        scanner.close();
    }
}