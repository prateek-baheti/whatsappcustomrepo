package com.whatsappcustom.whatsappcustom;

import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.BufferedWriter;
import java.io.FileWriter;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Arrays;
import java.util.Base64;
import java.security.SecureRandom;

@SpringBootApplication
public class WhatsappcustomApplication implements CommandLineRunner {

	public static void main(String[] args) {
		SpringApplication.run(WhatsappcustomApplication.class, args);
	}

	@Override
	public void run(String... args) {
		String passphrase = "yourPassphrase"; // Example passphrase, can be provided via args or prompt
		if (passphrase.isEmpty()) {
			throw new IllegalArgumentException("Passphrase is empty. Please provide a passphrase.");
		}

		generateKeyPair(passphrase);
	}

	public static void generateKeyPair(String passphrase) {
		try {
			// Step 1: Generate RSA key pair
			KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
			keyPairGenerator.initialize(2048); // Key size of 2048 bits
			KeyPair keyPair = keyPairGenerator.generateKeyPair();
			PrivateKey privateKey = keyPair.getPrivate();
			PublicKey publicKey = keyPair.getPublic();

			// Step 2: Derive a secret key from the passphrase using PBKDF2
			char[] passphraseChars = passphrase.toCharArray();
			byte[] salt = new byte[16]; // Salt for PBKDF2
			new SecureRandom().nextBytes(salt); // Generate random salt
			PBEKeySpec spec = new PBEKeySpec(passphraseChars, salt, 10000, 256); // 10,000 iterations, 256-bit key
			SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
			SecretKey secretKey = factory.generateSecret(spec);

			// Step 3: AES requires a 256-bit key, so ensure the derived key is of proper length
			byte[] aesKey = Arrays.copyOf(secretKey.getEncoded(), 32); // AES-256 key size (32 bytes)

			// Step 4: Generate random IV for AES CBC mode
			byte[] iv = new byte[16]; // 16 bytes for AES block size
			new SecureRandom().nextBytes(iv);
			IvParameterSpec ivParameterSpec = new IvParameterSpec(iv);

			// Step 5: Encrypt the private key with AES using CBC mode
			Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
			cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(aesKey, "AES"), ivParameterSpec);  // Use AES key and IV
			byte[] encryptedPrivateKey = cipher.doFinal(privateKey.getEncoded());

			// Step 6: Base64 encode both the encrypted private key and the public key
			String encryptedPrivateKeyBase64 = Base64.getEncoder().encodeToString(encryptedPrivateKey);
			String publicKeyBase64 = Base64.getEncoder().encodeToString(publicKey.getEncoded());

			// Output to console (this can be redirected to .env file or printed as required)
			System.out.println("************* COPY PASSPHRASE & PRIVATE KEY BELOW TO .env FILE *************");
			System.out.println("PASSPHRASE=\"" + passphrase + "\"");
			System.out.println("PRIVATE_KEY=\"" + encryptedPrivateKeyBase64 + "\"");
			System.out.println("************* COPY PASSPHRASE & PRIVATE KEY ABOVE TO .env FILE *************");
			System.out.println("************* COPY PUBLIC KEY BELOW *************");
			System.out.println(publicKeyBase64);
			System.out.println("************* COPY PUBLIC KEY ABOVE *************");

			// Optionally, write to a file (if desired)
			try (BufferedWriter writer = new BufferedWriter(new FileWriter(".env"))) {
				writer.write("PASSPHRASE=\"" + passphrase + "\"\n");
				writer.write("PRIVATE_KEY=\"" + encryptedPrivateKeyBase64 + "\"\n");
				writer.write("PUBLIC_KEY=\"" + publicKeyBase64 + "\"\n");
			}

		} catch (Exception e) {
			System.err.println("Error while creating public private key pair: " + e.getMessage());
			e.printStackTrace();
		}
	}
}
