package com.example.encryptedcomms;
import android.os.Bundle;
import android.os.Handler;
import android.os.Message;
import android.util.Base64;
import android.util.Log;
import android.view.View;
import android.widget.EditText;
import androidx.appcompat.app.AppCompatActivity;
import org.json.JSONObject;
import java.io.BufferedInputStream;
import java.io.BufferedReader;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.security.spec.X509EncodedKeySpec;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyAgreement;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKeyFactory;
import javax.crypto.ShortBufferException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;
public class MainActivity extends AppCompatActivity {
    String connectionURL = "https://10.0.2.2:443";
    public static PublicKey clientPublKey;
    public static PrivateKey clientPrivKey;
    public static PublicKey serverPublKey;
    public static SecretKeySpec sessionKey;
    public static IvParameterSpec iv;
    public Handler recvHandler = new Handler() {
        @Override
        public void handleMessage(Message inputMessage) {
            try {
                String b64Key = inputMessage.obj.toString();
                byte[] keyBytes = Base64.decode(b64Key, Base64.NO_WRAP);
                X509EncodedKeySpec spec = new X509EncodedKeySpec(keyBytes);
                KeyFactory kf;
                kf = KeyFactory.getInstance("EC");
                serverPublKey = kf.generatePublic(spec);
                Log.i("serverKey", "Received server key: " + bytesToHex(serverPublKey.getEncoded()));
            } catch (Exception e) {
                throw new RuntimeException(e);
            }
        }
    };
    public Handler msgHandler = new Handler() {
        @Override
        public void handleMessage(Message inputMessage) {
            try {
                Cipher cipher = Cipher.getInstance("AES/CBC/NoPadding");
                byte[] encMsg = Base64.decode(inputMessage.obj.toString(), Base64.NO_WRAP);
                cipher.init(Cipher.DECRYPT_MODE, MainActivity.sessionKey, MainActivity.iv);
                String msg = new String(cipher.doFinal(encMsg));
                Log.i("serverComms", "Decrypted message from server: " + msg);
            } catch (Exception e) {
                throw new RuntimeException(e);
            }
        }
    };
    @Override
    protected void onCreate(Bundle savedInstanceState) {
        try {
            super.onCreate(savedInstanceState);
            setContentView(R.layout.activity_main);
            KeyPairGenerator keyGen;
            keyGen = KeyPairGenerator.getInstance("EC");
            ECGenParameterSpec ecSpec = new ECGenParameterSpec("secp384r1");
            keyGen.initialize(ecSpec);
            KeyPair kp = keyGen.generateKeyPair();
            clientPublKey = kp.getPublic();
            Log.i("keyGen", "Generated public key: " + bytesToHex(clientPublKey.getEncoded()));
            clientPrivKey = kp.getPrivate();
            Log.i("keyGen", "Generated private key: " + bytesToHex(clientPrivKey.getEncoded()));
            byte[] IV = new byte[16];
            SecureRandom rand = new SecureRandom();
            rand.nextBytes(IV);
            iv = new IvParameterSpec(IV);
            TrustManager[] trustAllCerts = new TrustManager[]{
                    new X509TrustManager() {
                        public java.security.cert.X509Certificate[] getAcceptedIssuers() {
                            return null;
                        }
                        public void checkClientTrusted(
                                java.security.cert.X509Certificate[] certs, String authType) {
                        }
                        public void checkServerTrusted(
                                java.security.cert.X509Certificate[] certs, String authType) {
                        }
                    }
            };
            SSLContext sc = SSLContext.getInstance("TLS");
            sc.init(null, trustAllCerts, new java.security.SecureRandom());
            HttpsURLConnection.setDefaultSSLSocketFactory(sc.getSocketFactory());
            HttpsURLConnection.setDefaultHostnameVerifier(new NullHostNameVerifier());
        }
        catch(Exception e) {
            throw new RuntimeException(e);
        }
    }

    public void sendPk(View v) {
        String b64Key = Base64.encodeToString(clientPublKey.getEncoded(), Base64.NO_WRAP);
        Thread thr = new Thread(() -> {
            try {
                URL url = new URL(connectionURL + "/api/postPublicKey");
                HttpsURLConnection urlConn = (HttpsURLConnection) url.openConnection();
                urlConn.setRequestMethod("POST");
                urlConn.setRequestProperty( "Content-Type", "text/plain");
                urlConn.setRequestProperty( "Content-Length", Integer.toString(b64Key.getBytes().length));
                urlConn.setDoOutput(true);
                urlConn.getOutputStream().write(b64Key.getBytes("UTF-8"));
                urlConn.getResponseCode();
                Log.i("sentPk", "Sent public key to server successfully!");
                urlConn.disconnect();
            } catch (Exception e) {
                throw new RuntimeException(e);
            }
        });
        thr.start();
    }

    public void getPk(View v) throws InterruptedException, NoSuchAlgorithmException, InvalidKeyException, ShortBufferException, InvalidKeySpecException {
        Thread thr = new Thread(() -> {
            try {
                URL url = new URL(connectionURL + "/api/getPublicKey");
                HttpsURLConnection urlConnection = (HttpsURLConnection)url.openConnection();
                urlConnection.setRequestMethod("GET");
                urlConnection.connect();
                InputStream it = new BufferedInputStream(urlConnection.getInputStream());
                InputStreamReader read = new InputStreamReader(it);
                BufferedReader buff = new BufferedReader(read);
                StringBuilder dta = new StringBuilder();
                String chunks;
                while((chunks = buff.readLine()) != null) {
                    dta.append(chunks);
                }
                Message myMsg = recvHandler.obtainMessage();
                JSONObject jObj = new JSONObject(dta.toString());
                myMsg.obj = jObj.getString("publicKey");
                recvHandler.dispatchMessage(myMsg);
                urlConnection.disconnect();
            } catch (Exception e) {
                throw new RuntimeException(e);
            }
        });
        thr.start();
        thr.join();
        KeyAgreement sharedSecret = KeyAgreement.getInstance("ECDH");
        sharedSecret.init(clientPrivKey);
        sharedSecret.doPhase(serverPublKey, true);
        byte[] sharedSecretBytes = new byte[48];
        sharedSecret.generateSecret(sharedSecretBytes, 0);
        Log.i("sharedSec", "Generated shared secret on client side: " + bytesToHex(sharedSecretBytes));
        SecretKeyFactory fact = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
        KeySpec ks = new PBEKeySpec(Base64.encodeToString(sharedSecretBytes, Base64.NO_WRAP).toCharArray(), "mysalt".getBytes(), 100000, 256);
        sessionKey = new SecretKeySpec(fact.generateSecret(ks).getEncoded(), "AES");
        Log.i("sharedSec", "Generated derived key on client side: " + bytesToHex(sessionKey.getEncoded()));
    }

    public void sendMsg(View v) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        EditText tv = (EditText) findViewById(R.id.editText);
        String text = tv.getText().toString();
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, sessionKey, iv);
        byte[] encMsg = cipher.doFinal(text.getBytes());
        byte[] finalArr = new byte[16 + encMsg.length];
        for(int i = 0; i < 16; i++) {
            finalArr[i] = iv.getIV()[i];
        }
        for(int i = 16; i < finalArr.length; i++) {
            finalArr[i] = encMsg[i - 16];
        }
        Thread thr = new Thread(() -> {
            try {
                URL url = new URL(connectionURL + "/api/postMessage");
                HttpsURLConnection urlConn = (HttpsURLConnection) url.openConnection();
                urlConn.setRequestMethod("POST");
                urlConn.setRequestProperty( "Content-Type", "text/plain");
                urlConn.setRequestProperty( "Content-Length", Integer.toString(Base64.encodeToString(finalArr, Base64.NO_WRAP).getBytes().length));
                urlConn.setDoOutput(true);
                urlConn.getOutputStream().write(Base64.encodeToString(finalArr, Base64.NO_WRAP).getBytes());
                Log.i("serverComms", "Successfully sent encrypted message! Plain message: " + text);
                InputStream it = new BufferedInputStream(urlConn.getInputStream());
                InputStreamReader read = new InputStreamReader(it);
                BufferedReader buff = new BufferedReader(read);
                StringBuilder dta = new StringBuilder();
                String chunks;
                while((chunks = buff.readLine()) != null) {
                    dta.append(chunks);
                }
                Message myMsg = msgHandler.obtainMessage();
                myMsg.obj = dta.toString();
                msgHandler.dispatchMessage(myMsg);
                urlConn.disconnect();
            } catch (Exception e) {
                throw new RuntimeException(e);
            }
        });
        thr.start();
    }

    public static String bytesToHex(byte[] bytes) {
        final byte[] HEX_ARRAY = "0123456789ABCDEF".getBytes(StandardCharsets.US_ASCII);
        byte[] hexChars = new byte[bytes.length * 2];
        for (int j = 0; j < bytes.length; j++) {
            int v = bytes[j] & 0xFF;
            hexChars[j * 2] = HEX_ARRAY[v >>> 4];
            hexChars[j * 2 + 1] = HEX_ARRAY[v & 0x0F];
        }
        return new String(hexChars, StandardCharsets.UTF_8);
    }
}