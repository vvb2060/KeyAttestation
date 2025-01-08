package io.github.vvb2060.keyattestation.home

import android.os.Bundle
import androidx.fragment.app.commit
import io.github.vvb2060.keyattestation.BuildConfig
import io.github.vvb2060.keyattestation.R
import io.github.vvb2060.keyattestation.app.AppBarFragmentActivity

class HomeActivity : AppBarFragmentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        supportActionBar?.subtitle = BuildConfig.VERSION_NAME

        if (savedInstanceState == null) {
            supportFragmentManager.commit {
                setReorderingAllowed(true)
                add(R.id.fragment_container, HomeFragment())
            }
        }
    }
}
