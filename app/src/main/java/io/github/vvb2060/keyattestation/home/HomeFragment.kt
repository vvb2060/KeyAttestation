package io.github.vvb2060.keyattestation.home

import android.app.Dialog
import android.content.Context
import android.content.pm.PackageManager
import android.os.Bundle
import android.text.method.LinkMovementMethod
import android.view.*
import android.widget.ImageView
import android.widget.TextView
import androidx.appcompat.app.AlertDialog
import androidx.core.content.edit
import androidx.core.view.isVisible
import io.github.vvb2060.keyattestation.R
import io.github.vvb2060.keyattestation.app.AlertDialogFragment
import io.github.vvb2060.keyattestation.app.AppActivity
import io.github.vvb2060.keyattestation.app.AppFragment
import io.github.vvb2060.keyattestation.databinding.HomeBinding
import io.github.vvb2060.keyattestation.ktx.activityViewModels
import io.github.vvb2060.keyattestation.ktx.toHtml
import io.github.vvb2060.keyattestation.lang.AttestationException
import io.github.vvb2060.keyattestation.util.Status
import rikka.html.text.HtmlCompat
import rikka.widget.borderview.BorderView

class HomeFragment : AppFragment(), HomeAdapter.Listener {

    private var _binding: HomeBinding? = null

    private val binding: HomeBinding get() = _binding!!

    private val viewModel by activityViewModels { HomeViewModel(requireActivity()) }

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
        viewModel.preferIncludeProps = preference.getBoolean("prefer_including_props", true)
    }

    override fun onCreateView(inflater: LayoutInflater, container: ViewGroup?, savedInstanceState: Bundle?): View {
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

        binding.list.borderVisibilityChangedListener = BorderView.OnBorderVisibilityChangedListener { top: Boolean, _: Boolean, _: Boolean, _: Boolean -> appActivity?.appBar?.setRaised(!top) }
        binding.list.adapter = adapter
        binding.list.addItemDecoration(HomeItemDecoration(context))

        viewModel.hasStrongBox.observe(viewLifecycleOwner) {
            if (!it) {
                viewModel.preferStrongBox = false
            }
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
        menu.findItem(R.id.menu_use_strongbox).isVisible = viewModel.hasStrongBox.value == true
        menu.findItem(R.id.menu_use_strongbox).isChecked = viewModel.preferStrongBox
        menu.findItem(R.id.menu_incluid_props).isVisible = viewModel.hasDeviceIds.value == true
        menu.findItem(R.id.menu_incluid_props).isChecked = viewModel.preferIncludeProps
    }

    override fun onOptionsItemSelected(item: MenuItem): Boolean {
        return when (item.itemId) {
            R.id.menu_use_strongbox -> {
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
            }
            R.id.menu_about -> {
                val context = requireContext()
                val versionName: String
                try {
                    versionName = context.packageManager.getPackageInfo(context.packageName, 0).versionName
                } catch (ignored: PackageManager.NameNotFoundException) {
                    return true
                }
                val text = StringBuilder()
                text.append(versionName)
                        .append("<p>")
                        .append(getString(R.string.open_source_info, "<b><a href=\"${context.getString(R.string.github_url)}\">GitHub</a></b>", context.getString(R.string.license)))
                text.append("<p>").append(context.getString(R.string.copyright))

                val dialog: Dialog = AlertDialog.Builder(context)
                        .setView(rikka.material.R.layout.dialog_about)
                        .show()
                (dialog.findViewById<View>(rikka.material.R.id.design_about_icon) as ImageView).setImageDrawable(context.getDrawable(R.drawable.ic_launcher))
                (dialog.findViewById<View>(rikka.material.R.id.design_about_title) as TextView).text = getString(R.string.app_name)
                (dialog.findViewById<View>(rikka.material.R.id.design_about_version) as TextView).apply {
                    movementMethod = LinkMovementMethod.getInstance()
                    this.text = text.toHtml(HtmlCompat.FROM_HTML_OPTION_TRIM_WHITESPACE)
                }
                (dialog.findViewById<View>(rikka.material.R.id.design_about_info) as TextView).isVisible = false
                true
            }
            else -> super.onOptionsItemSelected(item)
        }
    }
}
