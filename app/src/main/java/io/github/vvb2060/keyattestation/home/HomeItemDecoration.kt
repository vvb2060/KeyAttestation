package io.github.vvb2060.keyattestation.home

import android.content.Context
import android.graphics.Canvas
import android.graphics.Rect
import android.graphics.drawable.Drawable
import android.view.View
import androidx.recyclerview.widget.RecyclerView
import androidx.recyclerview.widget.RecyclerView.ItemDecoration
import io.github.vvb2060.keyattestation.R
import rikka.core.res.resolveDrawable
import kotlin.math.roundToInt

class HomeItemDecoration(context: Context) : ItemDecoration() {

    private val drawable: Drawable = context.theme.resolveDrawable(R.attr.outlineButtonBackground)!!
    private val padding: Int = (context.resources.displayMetrics.density * 8).roundToInt()

    override fun getItemOffsets(outRect: Rect, view: View, parent: RecyclerView, state: RecyclerView.State) {
        val adapter = parent.adapter as HomeAdapter
        val position = parent.getChildAdapterPosition(view)
        if (adapter.shouldCommitFrameAt(position)) {
            outRect.bottom = padding
        }
        if (position == 0) {
            outRect.top = padding
        }
    }

    override fun onDrawOver(c: Canvas, parent: RecyclerView, state: RecyclerView.State) {
        if (parent.childCount == 0) {
            return
        }
        val adapter = parent.adapter as HomeAdapter
        var invalidatedPosition = true
        var left = 0
        var top = 0
        var right = 0
        var bottom: Int

        for (i in 0 until parent.childCount) {
            val child = parent.getChildAt(i)
            val position = parent.getChildAdapterPosition(child)

            if (!adapter.allowFrameAt(position)) {
                continue
            }

            if (invalidatedPosition) {
                left = child.left
                top = child.top
                right = child.right
                invalidatedPosition = false
            }

            if ((i == parent.childCount - 1) || adapter.shouldCommitFrameAt(position)) {
                bottom = child.bottom

                drawable.setBounds(left, top, right, bottom)
                drawable.draw(c)

                invalidatedPosition = true
            } else {
                left = child.left.coerceAtLeast(left)
                right = child.right.coerceAtLeast(right)
            }
        }
    }
}