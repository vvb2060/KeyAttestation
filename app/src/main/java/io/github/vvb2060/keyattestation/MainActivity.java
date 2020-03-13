package io.github.vvb2060.keyattestation;

import android.annotation.SuppressLint;
import android.app.Activity;
import android.content.Intent;
import android.content.pm.PackageManager;
import android.os.Build;
import android.os.Bundle;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;
import android.security.keystore.StrongBoxUnavailableException;
import android.util.Log;
import android.view.Menu;
import android.view.MenuItem;
import android.widget.Toast;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.GeneralSecurityException;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.ProviderException;
import java.security.cert.Certificate;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;
import java.security.spec.ECGenParameterSpec;
import java.util.Date;

import io.github.vvb2060.keyattestation.databinding.LayoutBinding;
import io.github.vvb2060.keyattestation.server.Attestation;
import io.github.vvb2060.keyattestation.server.RootOfTrust;
import io.github.vvb2060.keyattestation.server.VerifyCertificateChain;

public class MainActivity extends Activity {

    private static final String TAG = "KeyAttestation";
    private static final String ALIAS = "Key1";
    private static final int ORIGINATION_TIME_OFFSET = 1000000;
    private static final int CONSUMPTION_TIME_OFFSET = 2000000;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        LayoutBinding binding = LayoutBinding.inflate(getLayoutInflater());
        setContentView(binding.getRoot());
        StringBuilder sb = new StringBuilder(doAttestation(false));
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P &&
                getPackageManager().hasSystemFeature(PackageManager.FEATURE_STRONGBOX_KEYSTORE)) {
            sb.append("\n\n\n");
            sb.append(doAttestation(true));
        }
        binding.textView.setText(sb.toString());
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

    @SuppressLint("NewApi")
    void generateKey(boolean useStrongBox) throws GeneralSecurityException {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(
                KeyProperties.KEY_ALGORITHM_EC, "AndroidKeyStore");
        Date now = new Date();
        Date originationEnd = new Date(now.getTime() + ORIGINATION_TIME_OFFSET);
        Date consumptionEnd = new Date(now.getTime() + CONSUMPTION_TIME_OFFSET);
        KeyGenParameterSpec.Builder builder = new KeyGenParameterSpec
                .Builder(ALIAS, KeyProperties.PURPOSE_SIGN)
                .setAlgorithmParameterSpec(new ECGenParameterSpec("secp256r1"))
                .setKeyValidityStart(now)
                .setKeyValidityForOriginationEnd(originationEnd)
                .setKeyValidityForConsumptionEnd(consumptionEnd)
                .setAttestationChallenge("key attestation test".getBytes());
        if (useStrongBox) {
            builder.setDigests(KeyProperties.DIGEST_NONE, KeyProperties.DIGEST_SHA256);
            builder.setIsStrongBoxBacked(true);
        } else {
            builder.setDigests(KeyProperties.DIGEST_NONE, KeyProperties.DIGEST_SHA256, KeyProperties.DIGEST_SHA512);
        }
        keyPairGenerator.initialize(builder.build());
        keyPairGenerator.generateKeyPair();
    }

    @SuppressLint("NewApi")
    String doAttestation(boolean useStrongBox) {
        X509Certificate[] certs = null;
        StringBuilder sb = new StringBuilder();
        boolean isGoogleRootCertificate;
        try {
            KeyStore keyStore = KeyStore.getInstance("AndroidKeyStore");
            keyStore.load(null);
            generateKey(useStrongBox);
            Certificate[] certificates = keyStore.getCertificateChain(ALIAS);
            certs = new X509Certificate[certificates.length];
            for (int i = 0; i < certs.length; i++) certs[i] = (X509Certificate) certificates[i];
        } catch (ProviderException e) {
            if (e instanceof StrongBoxUnavailableException) {
                Log.e(TAG, "Strong box key attestation error.", e);
                sb.append("Strong box key attestation error. " + e.getLocalizedMessage() + "\n");
            } else {
                Log.e(TAG, "The device does not support key attestation.", e);
                sb.append("The device does not support key attestation. " + e.getLocalizedMessage() + "\n");
            }
            return sb.toString();
        } catch (Exception e) {
            Log.e(TAG, "Unable to get certificate.", e);
            if (certs == null) {
                sb.append("Unable to get certificate. " + e.getLocalizedMessage() + "\n");
                return sb.toString();
            }
        }

        try {
            isGoogleRootCertificate = VerifyCertificateChain.verifyCertificateChain(certs, getResources());
            if (isGoogleRootCertificate) sb.append("The root certificate is correct.\n\n");
            else sb.append("The root certificate is NOT correct.\n\n");
        } catch (Exception e) {
            Log.e(TAG, "Certificate is not trusted.", e);
            sb.append("Certificate is not trusted. " + e.getLocalizedMessage() + "\n");
            return sb.toString();
        }

        try {
            Attestation attestation = new Attestation(certs[0]);
            sb.append(attestation);
            showTrustedUnlockStatus(isGoogleRootCertificate, attestation);
        } catch (CertificateParsingException e) {
            Log.e(TAG, "Unable to parse attestation record.", e);
            sb.append("Unable to parse attestation record. " + e.getLocalizedMessage() + "\n");
        }
        return sb.toString();
    }

    void showTrustedUnlockStatus(boolean isGoogleRootCertificate, Attestation attestation) {
        if (isGoogleRootCertificate &&
                attestation.getAttestationSecurityLevel() != Attestation.KM_SECURITY_LEVEL_SOFTWARE) {
            RootOfTrust rootOfTrust = attestation.getTeeEnforced().getRootOfTrust();
            if (rootOfTrust != null) {
                if (rootOfTrust.isDeviceLocked()) getActionBar().setSubtitle("Locked");
                else getActionBar().setSubtitle("Unlocked");
                return;
            }
        }
        getActionBar().setSubtitle("Unknown");
    }
}
