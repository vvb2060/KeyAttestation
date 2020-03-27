package io.github.vvb2060.keyattestation.util

import android.view.View
import androidx.viewbinding.ViewBinding
import rikka.recyclerview.BaseListenerViewHolder

open class ViewBindingViewHolder<T, VB : ViewBinding, L>(itemView: View, internal val binding: VB) : BaseListenerViewHolder<T, L>(itemView) {

}