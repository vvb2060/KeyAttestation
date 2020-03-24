package io.github.vvb2060.keyattestation.home;

import android.app.Activity;
import android.content.Intent;
import android.os.Bundle;
import android.util.Log;
import android.view.Menu;
import android.view.MenuItem;
import android.widget.Toast;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;

import io.github.vvb2060.keyattestation.R;
import io.github.vvb2060.keyattestation.app.AppBarFragmentActivity;

import static io.github.vvb2060.keyattestation.Constants.TAG;

public class HomeActivity extends AppBarFragmentActivity {

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);

        if (savedInstanceState == null) {
            getSupportFragmentManager().beginTransaction()
                    .replace(R.id.fragment_container, new HomeFragment())
                    .commit();
        }
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

}
