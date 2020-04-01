package io.github.vvb2060.keyattestation.home;

import android.os.Bundle;
import android.view.Menu;

import io.github.vvb2060.keyattestation.R;
import io.github.vvb2060.keyattestation.app.AppBarFragmentActivity;

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
        getMenuInflater().inflate(R.menu.home, menu);
        return true;
    }
}
