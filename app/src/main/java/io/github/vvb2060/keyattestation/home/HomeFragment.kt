package io.github.vvb2060.keyattestation.home

import android.content.pm.PackageManager
import android.os.Build
import android.os.Bundle
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import androidx.core.view.isVisible
import androidx.fragment.app.viewModels
import androidx.lifecycle.observe
import io.github.vvb2060.keyattestation.R
import io.github.vvb2060.keyattestation.app.AlertDialogFragment
import io.github.vvb2060.keyattestation.app.AppActivity
import io.github.vvb2060.keyattestation.app.AppFragment
import io.github.vvb2060.keyattestation.databinding.HomeBinding
import io.github.vvb2060.keyattestation.ktx.toHtml
import io.github.vvb2060.keyattestation.lang.AttestationException
import io.github.vvb2060.keyattestation.util.Status
import rikka.html.text.HtmlCompat
import rikka.material.widget.BorderView.OnBorderVisibilityChangedListener

class HomeFragment : AppFragment(), HomeAdapter.Listener {

    private var _binding: HomeBinding? = null

    private val binding: HomeBinding get() = _binding!!

    private val viewModel by viewModels<HomeViewModel>({ requireActivity() })

    private val adapter by lazy {
        HomeAdapter(this)
    }

    override fun onCreateView(inflater: LayoutInflater, container: ViewGroup?, savedInstanceState: Bundle?): View? {
        _binding = HomeBinding.inflate(inflater, container, false)
        return binding.root
    }

    override fun onDestroyView() {
        super.onDestroyView()
        _binding = null
    }

    override fun onViewCreated(view: View, savedInstanceState: Bundle?) {
        super.onViewCreated(view, savedInstanceState)

        val context = view.context

        binding.list.borderVisibilityChangedListener = OnBorderVisibilityChangedListener { top: Boolean, _: Boolean, _: Boolean, _: Boolean -> appActivity?.appBar?.setRaised(!top) }
        binding.list.adapter = adapter
        binding.list.addItemDecoration(HomeItemDecoration(context))
    }

    override fun onActivityCreated(savedInstanceState: Bundle?) {
        super.onActivityCreated(savedInstanceState)

        val context = requireContext()

        viewModel.attestationResult.observe(viewLifecycleOwner) {
            when (it?.status) {
                Status.SUCCESS -> {
                    binding.progress.isVisible = false
                    binding.list.isVisible = true
                    adapter.updateData(it.data!!)
                }
                Status.ERROR -> {
                    binding.progress.isVisible = false
                    binding.list.isVisible = true
                    adapter.updateData(it.error as AttestationException)
                }
                Status.LOADING -> {
                    binding.progress.isVisible = true
                    binding.list.isVisible = false
                }
            }
        }
        val useStrongBox = Build.VERSION.SDK_INT >= Build.VERSION_CODES.P &&
                context.packageManager.hasSystemFeature(PackageManager.FEATURE_STRONGBOX_KEYSTORE)
        if (savedInstanceState == null) {
            viewModel.invalidateAttestation(context, useStrongBox)
        }
    }

    override fun onSubtitleDataClick(data: SubtitleData) {
        val context = requireContext()

        AlertDialogFragment.Builder(context)
                .title(data.title)
                .message(context.getString(data.description).toHtml(HtmlCompat.FROM_HTML_OPTION_TRIM_WHITESPACE))
                .positiveButton(android.R.string.ok)
                .build()
                .show(requireActivity().supportFragmentManager)
    }

    override fun onCommonDataClick(data: CommonData) {
        val context = requireContext()

        AlertDialogFragment.Builder(context)
                .title(data.title)
                .message(context.getString(data.description).toHtml(HtmlCompat.FROM_HTML_OPTION_TRIM_WHITESPACE))
                .positiveButton(android.R.string.ok)
                .build()
                .show(requireActivity().supportFragmentManager)
    }

    override fun onSecurityLevelDataClick(data: SecurityLevelData) {
        val context = requireContext()

        AlertDialogFragment.Builder(context)
                .title(data.title)
                .message("${context.getString(data.description)}<p>${context.getString(data.securityLevelDescription)}".toHtml(HtmlCompat.FROM_HTML_SEPARATOR_LINE_BREAK_LIST_ITEM or HtmlCompat.FROM_HTML_OPTION_TRIM_WHITESPACE))
                .positiveButton(android.R.string.ok)
                .build()
                .show((context as AppActivity).supportFragmentManager)
    }

    override fun onAuthorizationItemDataClick(data: AuthorizationItemData) {
        val context = requireContext()

        val message = if (!data.data.isNullOrBlank()) "${context.getString(data.description)}<p>* ${context.getString(if (data.tee) R.string.tee_enforced_description else R.string.sw_enforced_description)}"
                .toHtml(HtmlCompat.FROM_HTML_OPTION_TRIM_WHITESPACE)
        else
            context.getString(data.description).toHtml(HtmlCompat.FROM_HTML_OPTION_TRIM_WHITESPACE)

        AlertDialogFragment.Builder(context)
                .title(data.title)
                .message(message)
                .positiveButton(android.R.string.ok)
                .build()
                .show(requireActivity().supportFragmentManager)
    }
}