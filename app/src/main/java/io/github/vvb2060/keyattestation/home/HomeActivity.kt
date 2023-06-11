package io.github.vvb2060.keyattestation.home

import android.os.Bundle
import io.github.vvb2060.keyattestation.BuildConfig
import io.github.vvb2060.keyattestation.R
import io.github.vvb2060.keyattestation.app.AppBarFragmentActivity

class HomeActivity : AppBarFragmentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        supportActionBar?.subtitle = BuildConfig.VERSION_NAME

        if (savedInstanceState == null) {
            supportFragmentManager.beginTransaction()
                    .replace(R.id.fragment_container, HomeFragment())
                    .commit()
        }
    }
}
