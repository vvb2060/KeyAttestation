package io.github.vvb2060.keyattestation.home

import android.content.Context
import android.os.Bundle
import android.view.*
import androidx.core.content.edit
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

    private val preference by lazy {
        requireContext().getSharedPreferences("settings", Context.MODE_PRIVATE)
    }

    init {
        setHasOptionsMenu(true)
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        viewModel.preferStrongBox = preference.getBoolean("prefer_strongbox", true)
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

        viewModel.hasStrongBox.observe(viewLifecycleOwner) {
            activity?.invalidateOptionsMenu()
        }

        viewModel.attestationResults.observe(viewLifecycleOwner) {
            val res = it[if (viewModel.preferStrongBox) 1 else 0]
            when (res.status) {
                Status.SUCCESS -> {
                    binding.progress.isVisible = false
                    binding.list.isVisible = true
                    adapter.updateData(res.data!!)
                }
                Status.ERROR -> {
                    binding.progress.isVisible = false
                    binding.list.isVisible = true
                    adapter.updateData(res.error as AttestationException)
                }
                Status.LOADING -> {
                    binding.progress.isVisible = true
                    binding.list.isVisible = false
                }
            }
        }

        if (viewModel.attestationResults.value == null) {
            viewModel.invalidateAttestations(context)
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

    override fun onPrepareOptionsMenu(menu: Menu) {
        menu.findItem(R.id.use_strongbox).isVisible = viewModel.hasStrongBox.value == true
        menu.findItem(R.id.use_strongbox).isChecked = viewModel.preferStrongBox
    }

    override fun onOptionsItemSelected(item: MenuItem): Boolean {
        return if (item.itemId == R.id.use_strongbox) {
            item.isChecked = !item.isChecked
            viewModel.preferStrongBox = item.isChecked
            val index = if (viewModel.preferStrongBox) 1 else 0
            val res = viewModel.attestationResults.value?.get(index)
            if (res?.status == Status.SUCCESS) {
                adapter.updateData(res.data!!)
            } else if (res?.status == Status.ERROR) {
                adapter.updateData(res.error as AttestationException)
            }
            preference.edit { putBoolean("prefer_strongbox", item.isChecked) }
            true
        } else super.onOptionsItemSelected(item)
    }
}