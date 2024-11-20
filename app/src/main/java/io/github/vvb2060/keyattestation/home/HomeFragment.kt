package io.github.vvb2060.keyattestation.home

import android.app.Dialog
import android.content.Context
import android.os.Build
import android.os.Bundle
import android.text.method.LinkMovementMethod
import android.view.*
import android.widget.ImageView
import android.widget.TextView
import androidx.activity.result.contract.ActivityResultContracts.CreateDocument
import androidx.activity.result.contract.ActivityResultContracts.GetContent
import androidx.appcompat.app.AlertDialog
import androidx.core.view.MenuHost
import androidx.core.view.MenuProvider
import androidx.core.view.isVisible
import androidx.recyclerview.widget.LinearLayoutManager
import io.github.vvb2060.keyattestation.AppApplication
import io.github.vvb2060.keyattestation.BuildConfig
import io.github.vvb2060.keyattestation.R
import io.github.vvb2060.keyattestation.app.AlertDialogFragment
import io.github.vvb2060.keyattestation.app.AppActivity
import io.github.vvb2060.keyattestation.app.AppFragment
import io.github.vvb2060.keyattestation.attestation.Attestation
import io.github.vvb2060.keyattestation.attestation.CertificateInfo
import io.github.vvb2060.keyattestation.databinding.HomeBinding
import io.github.vvb2060.keyattestation.keystore.KeyStoreManager
import io.github.vvb2060.keyattestation.ktx.activityViewModels
import io.github.vvb2060.keyattestation.ktx.toHtml
import io.github.vvb2060.keyattestation.lang.AttestationException
import io.github.vvb2060.keyattestation.util.Status
import rikka.html.text.HtmlCompat
import rikka.shizuku.Shizuku
import rikka.widget.borderview.BorderView

class HomeFragment : AppFragment(), HomeAdapter.Listener, MenuProvider {

    private var _binding: HomeBinding? = null

    private val binding: HomeBinding get() = _binding!!

    private val viewModel by activityViewModels {
        val context = requireContext()
        val sp = context.getSharedPreferences("settings", Context.MODE_PRIVATE)
        HomeViewModel(context.packageManager, sp)
    }

    private val save = registerForActivityResult(CreateDocument("application/x-pkcs7-certificates")) {
        viewModel.save(requireContext().contentResolver, it)
    }

    private val load = registerForActivityResult(GetContent()) {
        viewModel.load(requireContext().contentResolver, it)
    }

    private val import = registerForActivityResult(GetContent()) {
        viewModel.import(requireContext().contentResolver, it)
    }

    private val adapter by lazy {
        HomeAdapter(this)
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
        (requireActivity() as MenuHost).addMenuProvider(this, viewLifecycleOwner)

        val context = view.context

        binding.list.borderVisibilityChangedListener = BorderView.OnBorderVisibilityChangedListener { top: Boolean, _: Boolean, _: Boolean, _: Boolean -> appActivity?.appBar?.setRaised(!top) }
        binding.list.layoutManager = LinearLayoutManager(context)
        binding.list.adapter = adapter
        binding.list.addItemDecoration(HomeItemDecoration(context))

        viewModel.getAttestationResult().observe(viewLifecycleOwner) { res ->
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

    override fun onAttestationInfoClick(data: Attestation) {
        val result = viewModel.getAttestationResult().value!!.data!!
        result.showAttestation = data
        adapter.updateData(result)
    }

    override fun onCertInfoClick(data: CertificateInfo) {
        val context = requireContext()

        AlertDialogFragment.Builder(context)
                .title(context.getString(R.string.cert_info))
                .message(data.cert.toString())
                .positiveButton(android.R.string.ok)
                .build()
                .show(requireActivity().supportFragmentManager)
    }

    override fun onCommonDataClick(data: Data) {
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

    override fun onPrepareMenu(menu: Menu) {
        menu.findItem(R.id.menu_use_shizuku).apply {
            isVisible = Shizuku.pingBinder()
            val received = KeyStoreManager.getRemoteKeyStore() != null
            if (!received) viewModel.preferShizuku = false
            isEnabled = received
            isChecked = viewModel.preferShizuku
        }
        menu.findItem(R.id.menu_import_attest_key)?.isVisible = viewModel.preferAttestKey
        menu.setGroupVisible(R.id.menu_id_type_group, viewModel.preferShizuku)
        menu.findItem(R.id.menu_include_unique_id).isVisible =
                viewModel.preferShizuku && viewModel.canIncludeUniqueId
        menu.findItem(R.id.menu_save).isVisible = viewModel.hasCertificates()
    }

    override fun onCreateMenu(menu: Menu, menuInflater: MenuInflater) {
        menuInflater.inflate(R.menu.home, menu)
        menu.findItem(R.id.menu_use_strongbox).isChecked = viewModel.preferStrongBox
        menu.findItem(R.id.menu_use_attest_key).isChecked = viewModel.preferAttestKey
        menu.findItem(R.id.menu_include_props).isChecked = viewModel.preferIncludeProps
        menu.findItem(R.id.menu_id_type_serial).isChecked = viewModel.preferIdAttestationSerial
        menu.findItem(R.id.menu_id_type_imei).isChecked = viewModel.preferIdAttestationIMEI
        menu.findItem(R.id.menu_id_type_meid).isChecked = viewModel.preferIdAttestationMEID
        menu.findItem(R.id.menu_include_unique_id).isChecked = viewModel.preferIncludeUniqueId
        if (!viewModel.hasStrongBox) {
            menu.removeItem(R.id.menu_use_strongbox)
        }
        if (!viewModel.hasAttestKey) {
            menu.removeItem(R.id.menu_use_attest_key)
            menu.removeItem(R.id.menu_import_attest_key)
        }
        if (!viewModel.hasDeviceIds) {
            menu.removeItem(R.id.menu_include_props)
            menu.removeItem(R.id.menu_id_type_serial)
            menu.removeItem(R.id.menu_id_type_imei)
            menu.removeItem(R.id.menu_id_type_meid)
        }
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.S) {
            menu.removeItem(R.id.menu_include_props)
        }
        if (!viewModel.hasIMEI) {
            menu.removeItem(R.id.menu_id_type_imei)
        }
        if (!viewModel.hasMEID) {
            menu.removeItem(R.id.menu_id_type_meid)
        }
    }

    override fun onMenuItemSelected(item: MenuItem): Boolean {
        when (item.itemId) {
            R.id.menu_use_shizuku -> {
                val status = !item.isChecked
                item.isChecked = status
                viewModel.preferShizuku = status
                viewModel.load()
            }
            R.id.menu_use_strongbox -> {
                val status = !item.isChecked
                item.isChecked = status
                viewModel.preferStrongBox = status
                viewModel.load()
            }
            R.id.menu_use_attest_key -> {
                val status = !item.isChecked
                item.isChecked = status
                viewModel.preferAttestKey = status
                viewModel.load()
            }
            R.id.menu_include_props -> {
                val status = !item.isChecked
                item.isChecked = status
                viewModel.preferIncludeProps = status
                viewModel.load()
            }
            R.id.menu_id_type_serial -> {
                val status = !item.isChecked
                item.isChecked = status
                viewModel.preferIdAttestationSerial = status
                viewModel.load()
            }
            R.id.menu_id_type_imei -> {
                val status = !item.isChecked
                item.isChecked = status
                viewModel.preferIdAttestationIMEI = status
                viewModel.load()
            }
            R.id.menu_id_type_meid -> {
                val status = !item.isChecked
                item.isChecked = status
                viewModel.preferIdAttestationMEID = status
                viewModel.load()
            }
            R.id.menu_include_unique_id -> {
                val status = !item.isChecked
                item.isChecked = status
                viewModel.preferIncludeUniqueId = status
                viewModel.load()
            }
            R.id.menu_reset -> {
                viewModel.load(true)
            }
            R.id.menu_save -> {
                save.launch("${Build.PRODUCT}-${AppApplication.TAG}.p7b")
            }
            R.id.menu_load -> {
                load.launch("application/*")
            }
            R.id.menu_import_attest_key -> {
                import.launch("text/xml")
            }
            R.id.menu_about -> {
                showAboutDialog()
            }
            else -> return false
        }
        return true
    }

    private fun showAboutDialog() {
        val context = requireContext()
        val text = StringBuilder()
        val source = "<b><a href=\"${context.getString(R.string.github_url)}\">GitHub</a></b>"
        val shizuku = "<b><a href=\"${context.getString(R.string.shizuku_url)}\">Web</a></b>"
        text.append(BuildConfig.VERSION_NAME).append("<p>")
        text.append(getString(R.string.open_source_info, source, context.getString(R.string.license)))
        if (Shizuku.pingBinder()) {
            KeyStoreManager.requestPermission()
        } else if (KeyStoreManager.isShizukuInstalled()) {
            KeyStoreManager.requestBinder(context)
            text.append("<p>").append(context.getString(R.string.start_shizuku))
        } else {
            text.append("<p>").append(context.getString(R.string.install_shizuku, shizuku))
        }
        text.append("<p>").append(context.getString(R.string.copyright))
        val icon = context.getDrawable(R.drawable.ic_launcher)
        val dialog: Dialog = AlertDialog.Builder(context)
                .setView(rikka.material.R.layout.dialog_about)
                .show()
        dialog.findViewById<TextView>(rikka.material.R.id.design_about_info).isVisible = false
        dialog.findViewById<ImageView>(rikka.material.R.id.design_about_icon).setImageDrawable(icon)
        dialog.findViewById<TextView>(rikka.material.R.id.design_about_title).text = getString(R.string.app_name)
        dialog.findViewById<TextView>(rikka.material.R.id.design_about_version).apply {
            movementMethod = LinkMovementMethod.getInstance()
            this.text = text.toHtml(HtmlCompat.FROM_HTML_OPTION_TRIM_WHITESPACE)
        }

    }
}
