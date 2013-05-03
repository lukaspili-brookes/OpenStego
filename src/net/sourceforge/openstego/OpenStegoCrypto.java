/*
 * Steganography utility to hide messages into cover files
 * Author: Samir Vaidya (mailto:syvaidya@gmail.com)
 * Copyright (c) 2007-2008 Samir Vaidya
 */

package net.sourceforge.openstego;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.security.Security;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.KeySpec;
import java.util.Date;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.PBEParameterSpec;

/**
 * This is the class for providing cryptography support to OpenStego.
 */
public class OpenStegoCrypto {

    private static final String AES_ALGORITHM = "PBEWITHSHA256AND128BITAES-CBC-BC";

    private static final String DES_ALGORITHM = "PBEWithMD5AndDES";

    private static final int MAX_ATTEMPS = 3;

    private static final int BLOCK_INTERVAL_SECONDS = 60;

    /**
     * 8-byte Salt for Password-based cryptography
     */
    private static final byte[] SALT = {(byte) 0x28, (byte) 0x5F, (byte) 0x71, (byte) 0xC9, (byte) 0x1E, (byte) 0x35,
            (byte) 0x0A, (byte) 0x62};

    /**
     * Iteration count for Password-based cryptography
     */
    private static final int ITER_COUNT = 7;

    /**
     * Cipher to use for encryption
     */
    private Cipher encryptCipher = null;

    /**
     * Cipher to use for decryption
     */
    private Cipher decryptCipher = null;

    private static int attempts = MAX_ATTEMPS;

    private static long blockedTimestamp;


    /**
     * Default constructor
     *
     * @param password Password to use for encryption
     * @throws OpenStegoException
     */
    public OpenStegoCrypto(String password, String algorithm) throws OpenStegoException {
        KeySpec keySpec = null;
        SecretKey secretKey = null;
        AlgorithmParameterSpec algoParamSpec = null;

        try {
            if (password == null) {
                password = "";
            }

            if (algorithm == null) {
                algorithm = OpenStegoConfig.CRYPTO_ALGORITHM_AES;
            }

            // Create the key
            keySpec = new PBEKeySpec(password.toCharArray(), SALT, ITER_COUNT);

            // get the secretkeyfactory using AES or DES
            SecretKeyFactory secretKeyFactory = (algorithm.equals(OpenStegoConfig.CRYPTO_ALGORITHM_AES)) ?
                    getAESSecretKeyFactory() : getDESSecretKeyFactory();

            secretKey = secretKeyFactory.generateSecret(keySpec);
            encryptCipher = Cipher.getInstance(secretKey.getAlgorithm());
            decryptCipher = Cipher.getInstance(secretKey.getAlgorithm());

            // Prepare cipher parameters
            algoParamSpec = new PBEParameterSpec(SALT, ITER_COUNT);

            // Initialize the ciphers
            encryptCipher.init(Cipher.ENCRYPT_MODE, secretKey, algoParamSpec);
            decryptCipher.init(Cipher.DECRYPT_MODE, secretKey, algoParamSpec);
        } catch (Exception ex) {
            if (ex instanceof OpenStegoException) {
                throw (OpenStegoException) ex;
            } else {
                throw new OpenStegoException(ex);
            }
        }
    }

    private SecretKeyFactory getAESSecretKeyFactory() throws Exception {
        // add the boucy castle JCE provider if needed
        if (Security.getProvider("BC") == null) {
            Security.addProvider(new BouncyCastleProvider());
        }

        return SecretKeyFactory.getInstance(AES_ALGORITHM);
    }

    private SecretKeyFactory getDESSecretKeyFactory() throws Exception {
        return SecretKeyFactory.getInstance(DES_ALGORITHM);
    }

    /**
     * Method to encrypt the data
     *
     * @param input Data to be encrypted
     * @return Encrypted data
     * @throws OpenStegoException
     */
    public byte[] encrypt(byte[] input) throws OpenStegoException {
        try {
            return encryptCipher.doFinal(input);
        } catch (Exception ex) {
            if (ex instanceof OpenStegoException) {
                throw (OpenStegoException) ex;
            } else {
                throw new OpenStegoException(ex);
            }
        }
    }

    /**
     * Method to decrypt the data
     *
     * @param input Data to be decrypted
     * @return Decrypted data (returns <code>null</code> if password is invalid)
     * @throws OpenStegoException
     */
    public byte[] decrypt(byte[] input) throws OpenStegoException {
        try {
            long interval = (new Date().getTime() - blockedTimestamp) / 1000;
            long remaining = BLOCK_INTERVAL_SECONDS - interval;
            if (attempts == 0 && remaining > 0) {
                throw new OpenStegoException(OpenStego.NAMESPACE, OpenStegoException.BLOCKED_INTERVAL, new String[]{String.valueOf(remaining)}, null);
            }

            byte[] res = decryptCipher.doFinal(input);
            attempts = MAX_ATTEMPS;
            return res;

        } catch (BadPaddingException bpEx) {
            attempts--;

            // means that the user was blocked then deblocked but still invalid password, start over
            if (attempts < 0) {
                attempts = MAX_ATTEMPS - 1;
            }

            if (attempts == 0) {
                blockedTimestamp = new Date().getTime();
            }

            throw new OpenStegoException(OpenStego.NAMESPACE, OpenStegoException.INVALID_PASSWORD, new String[]{String.valueOf(attempts)}, bpEx);
        } catch (Exception ex) {
            if (ex instanceof OpenStegoException) {
                throw (OpenStegoException) ex;
            } else {
                throw new OpenStegoException(ex);
            }
        }
    }
}
