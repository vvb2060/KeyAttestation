package io.github.vvb2060.keyattestation.home

import android.view.View
import io.github.vvb2060.keyattestation.databinding.HomeSubtitleBinding

class SubtitleViewHolder(itemView: View, binding: HomeSubtitleBinding) :
    HomeViewHolder<Data, HomeSubtitleBinding>(itemView, binding) {

    companion object {

        val CREATOR = Creator<Data> { inflater, parent ->
            val binding = HomeSubtitleBinding.inflate(inflater, parent, false)
            SubtitleViewHolder(binding.root, binding)
        }
    }

    init {
        itemView.setOnClickListener {
            listener.onCommonDataClick(data)
        }
    }

    override fun onBind() {
        binding.title.setText(data.title)
    }
}
