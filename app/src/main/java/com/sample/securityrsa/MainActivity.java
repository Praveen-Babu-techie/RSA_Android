package com.sample.securityrsa;

import androidx.appcompat.app.AppCompatActivity;

import android.os.Bundle;
import android.text.Editable;
import android.util.Base64;
import android.view.View;
import android.widget.Button;
import android.widget.EditText;

import java.io.IOException;
import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAPrivateKeySpec;
import java.security.spec.RSAPublicKeySpec;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

public class MainActivity extends AppCompatActivity {
    public static BigInteger publicModulus;
    public static BigInteger publicExponent;

    public static BigInteger privateModulus;
    public static BigInteger privateExponent;
    private EditText etInput;
    private EditText etOutput;
    private Button EncryptButton;
    private Button DecryptButton;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);
        etInput=(EditText)findViewById(R.id.etInput);
        etOutput=(EditText)findViewById(R.id.etOutput);
        EncryptButton=(Button)findViewById(R.id.encrypt);
        DecryptButton=(Button)findViewById(R.id.decrypt);

        try {
            generateAndSaveRsaKey();
        } catch (IOException e) {
            e.printStackTrace();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (InvalidKeySpecException e) {
            e.printStackTrace();
        }



        EncryptButton.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View view)
            {
            String s=etInput.getText().toString();

                try {
                    String cipherText=rsaEncrypt(s);

                    etOutput.setText(cipherText);
                } catch (NoSuchPaddingException e) {
                    e.printStackTrace();
                } catch (NoSuchAlgorithmException e) {
                    e.printStackTrace();
                } catch (IOException e) {
                    e.printStackTrace();
                } catch (InvalidKeyException e) {
                    e.printStackTrace();
                } catch (BadPaddingException e) {
                    e.printStackTrace();
                } catch (IllegalBlockSizeException e) {
                    e.printStackTrace();
                }

            }
        });

        DecryptButton.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View view) {
                String s=etOutput.getText().toString();
                try {
                    String plainText=rsaDecrypt(s);
                    etInput.setText(plainText);
                } catch (NoSuchPaddingException e) {
                    e.printStackTrace();
                } catch (NoSuchAlgorithmException e) {
                    e.printStackTrace();
                } catch (IOException e) {
                    e.printStackTrace();
                } catch (InvalidKeyException e) {
                    e.printStackTrace();
                } catch (BadPaddingException e) {
                    e.printStackTrace();
                } catch (IllegalBlockSizeException e) {
                    e.printStackTrace();
                }

            }});



    }
    public void generateAndSaveRsaKey() throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {

        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(1024); // you can decrease and increase this as per requirement
        KeyPair kp = kpg.genKeyPair();
        Key publicKey = kp.getPublic();
        Key privateKey = kp.getPrivate();

        KeyFactory fact = KeyFactory.getInstance("RSA");
        RSAPublicKeySpec pub = fact.getKeySpec(publicKey,
                RSAPublicKeySpec.class);
        RSAPrivateKeySpec priv = fact.getKeySpec(privateKey,
                RSAPrivateKeySpec.class);

        publicModulus = pub.getModulus();
        publicExponent = pub.getPublicExponent();
        privateModulus = priv.getModulus();
        privateExponent = priv.getPrivateExponent();

    }

    public PublicKey readPublicKey() throws IOException {

        try {

            RSAPublicKeySpec keySpec = new RSAPublicKeySpec(publicModulus, publicExponent);
            KeyFactory fact = KeyFactory.getInstance("RSA");
            PublicKey pubKey = fact.generatePublic(keySpec);
            return pubKey;
        } catch (Exception e) {
            throw new RuntimeException("Spurious serialisation error", e);
        }
    }

    public PrivateKey readPrivateKey() throws IOException {

        try {

            RSAPrivateKeySpec keySpec = new RSAPrivateKeySpec(privateModulus, privateExponent);
            KeyFactory fact = KeyFactory.getInstance("RSA");
            PrivateKey priKey = fact.generatePrivate(keySpec);
            return priKey;
        } catch (Exception e) {
            throw new RuntimeException("Spurious serialisation error", e);
        }
    }
    public String rsaEncrypt(String data) throws NoSuchPaddingException, NoSuchAlgorithmException, IOException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        PublicKey pubKey = readPublicKey();
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.ENCRYPT_MODE, pubKey);
        byte[] cipherData = cipher.doFinal(data.getBytes());
        return Base64.encodeToString(cipherData,1);
                //Base64.encodeToString(cipherData);
    }

    public String rsaDecrypt(String data) throws NoSuchPaddingException, NoSuchAlgorithmException, IOException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        PrivateKey pubKey = readPrivateKey();
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.DECRYPT_MODE, pubKey);
        byte[] cipherData = cipher.doFinal(Base64.decode(data,1));
        return new String(cipherData);
    }






}

