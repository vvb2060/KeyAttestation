package io.github.vvb2060.keyattestation.util

import android.view.View
import androidx.viewbinding.ViewBinding
import rikka.recyclerview.BaseViewHolder

open class ViewBindingViewHolder<T, VB : ViewBinding>(itemView: View, internal val binding: VB) : BaseViewHolder<T>(itemView) {

}