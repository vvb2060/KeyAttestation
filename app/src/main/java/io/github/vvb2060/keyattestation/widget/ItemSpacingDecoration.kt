package io.github.vvb2060.keyattestation.widget

import android.content.Context
import android.graphics.Rect
import android.view.View
import androidx.recyclerview.widget.RecyclerView
import androidx.recyclerview.widget.RecyclerView.ItemDecoration
import kotlin.math.roundToInt

class ItemSpacingDecoration(context: Context, paddingDp: Int = 8) : ItemDecoration() {

    private val padding: Int = (context.resources.displayMetrics.density * paddingDp).roundToInt()

    override fun getItemOffsets(outRect: Rect, view: View, parent: RecyclerView, state: RecyclerView.State) {
        outRect.bottom = padding
        if (parent.layoutManager?.getPosition(view) == 0) {
            outRect.top = padding
        }
    }
}