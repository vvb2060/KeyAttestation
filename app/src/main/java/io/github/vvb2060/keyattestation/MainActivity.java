package io.github.vvb2060.keyattestation;

import android.app.Activity;
import android.content.Intent;
import android.os.Bundle;
import android.os.StrictMode;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;
import android.util.Log;
import android.view.Menu;
import android.view.MenuItem;
import android.widget.Toast;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.ProviderException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.security.spec.ECGenParameterSpec;
import java.util.Date;

import io.github.vvb2060.keyattestation.databinding.LayoutBinding;

public class MainActivity extends Activity {

    private static final String TAG = KeyAttestation.class.getCanonicalName();
    private static final String ALIAS = "Key1";

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        StrictMode.ThreadPolicy policy = new StrictMode.ThreadPolicy.Builder().permitNetwork().build();
        StrictMode.setThreadPolicy(policy);
        LayoutBinding binding = LayoutBinding.inflate(getLayoutInflater());
        setContentView(binding.getRoot());
        binding.textView.setText(doAttestation());
    }

    @Override
    public boolean onCreateOptionsMenu(Menu menu) {
        getMenuInflater().inflate(R.menu.menu, menu);
        return true;
    }

    @Override
    public boolean onOptionsItemSelected(MenuItem item) {
        if (item.getItemId() == R.id.logcat) {
            Intent intent = new Intent(Intent.ACTION_CREATE_DOCUMENT)
                    .addCategory(Intent.CATEGORY_OPENABLE)
                    .setType("text/plain")
                    .putExtra(Intent.EXTRA_TITLE, "KeyAttestation.log");
            startActivityForResult(intent, 42);
            return true;
        } else return super.onOptionsItemSelected(item);
    }

    @Override
    protected void onActivityResult(int requestCode, int resultCode, Intent data) {
        if (resultCode == Activity.RESULT_OK) {
            if (requestCode == 42 && data.getData() != null) {
                try {
                    OutputStream outputStream = getContentResolver().openOutputStream(data.getData());
                    InputStream inputStream = Runtime.getRuntime().exec("logcat -d -v long").getInputStream();
                    assert outputStream != null;
                    byte[] buffer = new byte[8 * 1024];
                    int bytes;
                    while ((bytes = inputStream.read(buffer)) >= 0)
                        outputStream.write(buffer, 0, bytes);
                } catch (IOException e) {
                    Log.e(TAG, "Unable to save log.", e);
                    Toast.makeText(this, "Unable to save log. " + e.getLocalizedMessage(), Toast.LENGTH_SHORT).show();
                }
            }
        } else super.onActivityResult(requestCode, resultCode, data);
    }

    void generateKey() throws NoSuchProviderException, NoSuchAlgorithmException,
            InvalidAlgorithmParameterException {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(
                KeyProperties.KEY_ALGORITHM_EC, "AndroidKeyStore");
        KeyGenParameterSpec.Builder builder = new KeyGenParameterSpec
                .Builder(ALIAS, KeyProperties.PURPOSE_SIGN)
                .setAlgorithmParameterSpec(new ECGenParameterSpec("P-256"))
                .setDigests(KeyProperties.DIGEST_SHA256, KeyProperties.DIGEST_SHA512)
                .setCertificateNotBefore(new Date())
                .setAttestationChallenge("key attestation test".getBytes());
        keyPairGenerator.initialize(builder.build());
        try {
            keyPairGenerator.generateKeyPair();
        } catch (ProviderException e) {
            Log.e(TAG, "The device does not support key attestation.", e);
            builder.setAttestationChallenge(null);
            keyPairGenerator.initialize(builder.build());
            keyPairGenerator.generateKeyPair();
        }
    }

    Certificate[] getCerts() throws KeyStoreException, CertificateException,
            NoSuchAlgorithmException, IOException, NoSuchProviderException,
            InvalidAlgorithmParameterException {
        KeyStore keyStore = KeyStore.getInstance("AndroidKeyStore");
        keyStore.load(null);
        Certificate[] certs = keyStore.getCertificateChain(ALIAS);
        if (certs == null) {
            generateKey();
            certs = keyStore.getCertificateChain(ALIAS);
        }
        return certs;
    }

    String doAttestation() {
        X509Certificate[] certs = null;
        StringBuilder sb = new StringBuilder();
        try {
            Certificate[] certificates = getCerts();
            certs = new X509Certificate[certificates.length];
            for (int i = 0; i < certs.length; i++) certs[i] = (X509Certificate) certificates[i];
        } catch (Exception e) {
            Log.e(TAG, "Unable to get certificate.", e);
            if (certs == null) {
                sb.append("Unable to get certificate.").append(e.getLocalizedMessage()).append('\n');
                return sb.toString();
            }
        }

        try {
            KeyAttestation.verifyCertificateChain(sb, certs, getResources());
        } catch (Exception e) {
            Log.e(TAG, "Certificate is not trusted.", e);
            sb.append("Certificate is not trusted.").append(e.getLocalizedMessage()).append('\n');
            return sb.toString();
        }

        try {
            sb.append(KeyAttestation.parseAttestationRecord(certs));
        } catch (IOException e) {
            Log.e(TAG, "Unable to extract attestation sequence.", e);
            sb.append("Unable to extract attestation sequence.").append(e.getLocalizedMessage()).append('\n');
        } catch (IllegalArgumentException e) {
            Log.e(TAG, "Unable to parse attestation record.", e);
            sb.append("Unable to parse attestation record.").append(e.getLocalizedMessage()).append('\n');
        }
        return sb.toString();
    }
}