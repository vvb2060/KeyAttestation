package io.github.vvb2060.keyattestation.app

import android.graphics.Color
import android.os.Bundle
import android.view.View
import android.view.ViewGroup
import android.widget.FrameLayout
import androidx.annotation.LayoutRes
import androidx.appcompat.widget.Toolbar
import io.github.vvb2060.keyattestation.R
import rikka.material.widget.AppBarLayout

abstract class AppBarActivity : AppActivity() {

    private val rootView: ViewGroup by lazy {
        findViewById<ViewGroup>(R.id.root)
    }

    private val toolbarContainer: AppBarLayout by lazy {
        findViewById<AppBarLayout>(R.id.toolbar_container)
    }

    private val toolbar: Toolbar by lazy {
        findViewById<Toolbar>(R.id.toolbar)
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        super.setContentView(getLayoutId())

        setAppBar(toolbarContainer, toolbar)
    }

    @LayoutRes
    open fun getLayoutId(): Int {
        return R.layout.appbar_activity
    }

    override fun setContentView(layoutResID: Int) {
        layoutInflater.inflate(layoutResID, rootView, true)
        rootView.bringChildToFront(toolbarContainer)
    }

    override fun setContentView(view: View?) {
        setContentView(view, FrameLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.MATCH_PARENT))
    }

    override fun setContentView(view: View?, params: ViewGroup.LayoutParams?) {
        rootView.addView(view, 0, params)
    }

    override fun shouldApplyTranslucentSystemBars(): Boolean {
        return true
    }

    override fun onApplyTranslucentSystemBars() {
        super.onApplyTranslucentSystemBars()
        window?.statusBarColor = Color.TRANSPARENT
    }
}

abstract class AppBarFragmentActivity : AppBarActivity() {

    override fun getLayoutId(): Int {
        return R.layout.appbar_fragment_activity
    }
}
