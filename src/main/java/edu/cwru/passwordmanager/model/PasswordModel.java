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

    private void loadPasswords() {
        // TODO: Replace with loading passwords from file, you will want to add them to the passwords list defined above
        // TODO: Tips: Use buffered reader, make sure you split on separator, make sure you decrypt password

        try (BufferedReader reader = new BufferedReader(new FileReader(passwordFile))) {
            // salt and token handled
            reader.readLine();

            String line;
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

    public PasswordModel() {
        loadPasswords();
    }

    static public boolean passwordFileExists() {
        return passwordFile.exists();
    }

    static public void initializePasswordFile(String password) throws IOException {
        passwordFile.createNewFile();

        // TODO: Use password to create token and save in file with salt (TIP: Save these just like you would save password)
        passwordFilePassword = password;

        try {
            passwordFileSalt = generateSalt();
            passwordFileKey = generateKey(password,passwordFileSalt);

            writeFile(new ArrayList<>());
        } catch (GeneralSecurityException e) {
            throw new RuntimeException(e);
        }
    }

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

            return decrypt(parts[1]).equals(verifyString);
        } catch (Exception e) {
            // wrong password or file
            return false;
        }
    }

    public ObservableList<Password> getPasswords() {
        return passwords;
    }

    public void deletePassword(int index) {
        passwords.remove(index);

        // TODO: Remove it from file
        saveFile();
    }

    public void updatePassword(Password password, int index) {
        passwords.set(index, password);

        // TODO: Update the file with the new password information
        saveFile();
    }

    public void addPassword(Password password) {
        passwords.add(password);

        // TODO: Add the new password to the file
        saveFile();
    }

    // TODO: Tip: Break down each piece into individual methods, for example: generateSalt(), encryptPassword, generateKey(), saveFile, etc ...
    // TODO: Use these functions above, and it will make it easier! Once you know encryption, decryption, etc works, you just need to tie them in

    static private byte [] generateSalt() {
        SecureRandom random = new SecureRandom();
        byte [] salt = new byte[16];
        random.nextBytes(salt);
        return salt;
    }

    static private byte [] generateKey(String password,byte [] salt) throws GeneralSecurityException {
        KeySpec spec = new PBEKeySpec(password.toCharArray(), salt, 600000, 128);
        SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
        return factory.generateSecret(spec).getEncoded();
    }

    static private String encrypt(String message) throws GeneralSecurityException {
        Cipher cipher = Cipher.getInstance("AES");
        SecretKeySpec key = new SecretKeySpec(passwordFileKey, "AES");
        cipher.init(Cipher.ENCRYPT_MODE, key);

        byte [] encryptedData = cipher.doFinal(message.getBytes());
        return Base64.getEncoder().encodeToString(encryptedData);
    }

    static private String decrypt(String message) throws GeneralSecurityException {
        Cipher cipher = Cipher.getInstance("AES");
        SecretKeySpec key = new SecretKeySpec(passwordFileKey, "AES");
        cipher.init(Cipher.DECRYPT_MODE, key);

        byte [] encryptedData = Base64.getDecoder().decode(message);
        byte [] decryptedData = cipher.doFinal(encryptedData);
        return new String(decryptedData);
    }

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

    private void saveFile() {
        try {
            writeFile(passwords);
        } catch (IOException | GeneralSecurityException e ) {
            throw new RuntimeException(e);
        }
    }


}
