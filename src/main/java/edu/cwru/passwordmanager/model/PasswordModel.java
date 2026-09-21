package edu.cwru.passwordmanager.model;

import javafx.collections.FXCollections;
import javafx.collections.ObservableList;

import javax.crypto.*;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import java.security.spec.KeySpec;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;

/**
 * The class that represents the Password book.
 *
 * @author isabellacraun
 */
public class PasswordModel {
    private ObservableList<Password> passwords = FXCollections.observableArrayList();

    // !!! DO NOT CHANGE - VERY IMPORTANT FOR GRADING !!!
    static private File passwordFile = new File("passwords.txt");

    static private String separator = "\t";

    static private String passwordFilePassword = "";
    static private byte [] passwordFileKey;
    static private byte [] passwordFileSalt;

    // TODO: You can set this to whatever you like to verify that the password the user entered is correct
    private static String verifyString = "cookies";

    /**
     * A method to load saved passwords from {@link #passwordFile} into {@link #passwords}.
     *
     * <p>Skips first line with salt and verification token. Decrypts passwords after that
     * with current {@link #passwordFileKey}.
     * That key must be set prior with call to {@link #verifyPassword(String)} or
     * {@link #initializePasswordFile(String)}.
     *
     * @throws RuntimeException if cannot read file or decrypt password
     */
    private void loadPasswords() {
        // TODO: Replace with loading passwords from file, you will want to add them to the passwords list defined above
        // TODO: Tips: Use buffered reader, make sure you split on separator, make sure you decrypt password

        try (BufferedReader reader = new BufferedReader(new FileReader(passwordFile))) {
            // salt and token handled
            reader.readLine();

            String line;
            // loop should skip extraneous lines
            while ((line = reader.readLine()) != null) {
                String [] parts = line.split(separator);
                if (parts.length < 2) {
                    continue;
                }

                String label = parts[0];
                String password = decrypt(parts[1]);
                passwords.add(new Password(label, password));
            }
        } catch (IOException | GeneralSecurityException e) {
            throw new RuntimeException(e);
        }
    }

    /**
     * A method to create a model and load existing passwords.
     *
     * <p>Assumes the password file's key has been set up prior with
     * {@link #verifyPassword(String)} or {@link #initializePasswordFile(String)}.
     */
    public PasswordModel() {
        loadPasswords();
    }

    /**
     * A method to check is password book file exists on disk.
     *
     * @return {@code true} if {@link #passwordFile} exists
     *         {@code false} otherwise
     */
    static public boolean passwordFileExists() {
        return passwordFile.exists();
    }

    /**
     * A method to create a new password book file protected with input password.
     *
     * <p>Will generate a random salt to derive an encryption key with password.
     * Writes the salt and verification token to the file.
     *
     * @param password the password protecting access to the file
     * @throws IOException the file cannot be created or written to
     */
    static public void initializePasswordFile(String password) throws IOException {
        passwordFile.createNewFile();

        // TODO: Use password to create token and save in file with salt (TIP: Save these just like you would save password)
        passwordFilePassword = password;

        try {
            passwordFileSalt = generateSalt();
            passwordFileKey = generateKey(password,passwordFileSalt);

            // writes the salt and v token
            writeFile(new ArrayList<>());
        } catch (GeneralSecurityException e) {
            throw new RuntimeException(e);
        }
    }

    /**
     * A method to check if the input password unlocks the password file.
     *
     * <p>Will read the salt and verification token from first line of file,
     * derive a key from password, and attempt to decrypt token. If succeeds,
     * will store the derived key.
     *
     * @param password the password user entered
     * @return {@code true} if token decrypts and matches string
     *         {@code false} if password or file is wrong
     */
    static public boolean verifyPassword(String password) {
        passwordFilePassword = password; // DO NOT CHANGE

        // TODO: Check first line and use salt to verify that you can decrypt the token using the password from the user
        // TODO: TIP !!! If you get an exception trying to decrypt, that also means they have the wrong passcode, return false!

        try (BufferedReader reader = new BufferedReader(new FileReader(passwordFile))) {
            String line = reader.readLine();
            if (line == null) {
                return false;
            }
            String [] parts = line.split(separator);
            passwordFileSalt = Base64.getDecoder().decode(parts[0]);
            passwordFileKey = generateKey(password, passwordFileSalt);

            // prevent edge case of bad key slipping through exception
            return decrypt(parts[1]).equals(verifyString);
        } catch (Exception e) {
            // wrong password or file
            return false;
        }
    }

    /**
     * A method to return the current list of passwords in memory.
     *
     * <p>Same list backing UI, so add and remove is reflected on screen.
     *
     * @return the list of saved passwords
     */
    public ObservableList<Password> getPasswords() {
        return passwords;
    }

    /**
     * A method to remove the password at the given index and update file on disk.
     *
     * @param index of the password to remove, seen in {@link #passwords}
     */
    public void deletePassword(int index) {
        passwords.remove(index);

        // TODO: Remove it from file
        saveFile();
    }

    /**
     * A method to replace the password at the given index and update file on disk.
     *
     * @param password the new label/password to store at {@code index}
     * @param index of the password to replace, seen in {@link #passwords}
     */
    public void updatePassword(Password password, int index) {
        passwords.set(index, password);

        // TODO: Update the file with the new password information
        saveFile();
    }

    /**
     * A method to add new password to end of list and update file on disk.
     *
     * @param password the new label/password to add
     */
    public void addPassword(Password password) {
        passwords.add(password);

        // TODO: Add the new password to the file
        saveFile();
    }

    // TODO: Tip: Break down each piece into individual methods, for example: generateSalt(), encryptPassword, generateKey(), saveFile, etc ...
    // TODO: Use these functions above, and it will make it easier! Once you know encryption, decryption, etc works, you just need to tie them in

    /**
     * A helper method to generate a new random 16 byte salt.
     *
     * @return the salt, suitable for {@link #generateKey(String, byte[])}.
     */
    static private byte [] generateSalt() {
        SecureRandom random = new SecureRandom();
        byte [] salt = new byte[16];
        random.nextBytes(salt);
        return salt;
    }

    /**
     * A helper method to create 128 bit AES key from password and salt using PBKDF2.
     *
     * @param password to derive the key from
     * @param salt to combine with password
     * @return the created key, as raw bytes suitable for {@link SecretKeySpec}
     * @throws GeneralSecurityException derivation algorithm unavailable
     */
    static private byte [] generateKey(String password,byte [] salt) throws GeneralSecurityException {
        KeySpec spec = new PBEKeySpec(password.toCharArray(), salt, 600000, 128);
        SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
        return factory.generateSecret(spec).getEncoded();
    }

    /**
     * A helper method to encrypt message using {@link #passwordFileKey}.
     *
     * @param message to encrypt
     * @return encrypted message, encoded as Base64 to be stored as text
     * @throws GeneralSecurityException cipher cannot run
     */
    static private String encrypt(String message) throws GeneralSecurityException {
        Cipher cipher = Cipher.getInstance("AES");
        SecretKeySpec key = new SecretKeySpec(passwordFileKey, "AES");
        cipher.init(Cipher.ENCRYPT_MODE, key);

        byte [] encryptedData = cipher.doFinal(message.getBytes());
        return Base64.getEncoder().encodeToString(encryptedData);
    }

    /**
     * A helper method to decrypt message using {@link #passwordFileKey}.
     *
     * @param message encrypted, encoded as Base64
     * @return decrypted plaintext message
     * @throws GeneralSecurityException cipher cannot initialize or decrypt fails
     */
    static private String decrypt(String message) throws GeneralSecurityException {
        Cipher cipher = Cipher.getInstance("AES");
        SecretKeySpec key = new SecretKeySpec(passwordFileKey, "AES");
        cipher.init(Cipher.DECRYPT_MODE, key);

        byte [] encryptedData = Base64.getDecoder().decode(message);
        byte [] decryptedData = cipher.doFinal(encryptedData);
        return new String(decryptedData);
    }

    /**
     * A helper method to rewrite password file from scratch.
     *
     * <p>Will write salt and verification token on first line, then one line
     * for each password with its label and encrypted password.
     *
     * @param passwords to write, in order
     * @throws IOException cannot write to file
     * @throws GeneralSecurityException cannot encrypt password
     */
    static private void writeFile(List<Password> passwords) throws IOException, GeneralSecurityException {
        try (BufferedWriter writer = new BufferedWriter(new FileWriter(passwordFile))) {
            String saltString = Base64.getEncoder().encodeToString(passwordFileSalt);
            writer.write(saltString + separator + encrypt(verifyString));
            writer.newLine();

            for (Password password : passwords) {
                writer.write(password.getLabel() + separator + encrypt(password.getPassword()));
                writer.newLine();
            }
        }
    }

    /**
     * A helper method to save {@link #passwords} list in memory to disk.
     *
     * <p>Thin wrapper around {@link #writeFile(List)} to simplify
     * {@link #addPassword}, {@link #updatePassword}, and {@link #deletePassword}
     * from individual checked exception handling.
     *
     * @throws RuntimeException cannot write to file
     */
    private void saveFile() {
        try {
            writeFile(passwords);
        } catch (IOException | GeneralSecurityException e ) {
            throw new RuntimeException(e);
        }
    }


}
