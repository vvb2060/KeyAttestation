package io.github.vvb2060.keyattestation.home

import android.view.View
import androidx.viewbinding.ViewBinding
import io.github.vvb2060.keyattestation.util.ViewBindingViewHolder

abstract class HomeViewHolder<T, VB : ViewBinding>(itemView: View, binding: VB) : ViewBindingViewHolder<T, VB, HomeAdapter.Listener>(itemView, binding)