package io.github.vvb2060.keyattestation.home

import android.content.pm.PackageManager
import android.os.Build
import android.os.Bundle
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import androidx.fragment.app.viewModels
import androidx.lifecycle.observe
import io.github.vvb2060.keyattestation.app.AppFragment
import io.github.vvb2060.keyattestation.attestation.Attestation
import io.github.vvb2060.keyattestation.databinding.HomeBinding
import io.github.vvb2060.keyattestation.util.Status
import rikka.material.widget.BorderView.OnBorderVisibilityChangedListener

class HomeFragment : AppFragment() {

    private lateinit var binding: HomeBinding

    private val viewModel by viewModels<HomeViewModel>({ requireActivity() })

    override fun onCreateView(inflater: LayoutInflater, container: ViewGroup?, savedInstanceState: Bundle?): View? {
        binding = HomeBinding.inflate(inflater, container, false)
        return binding.root
    }

    override fun onViewCreated(view: View, savedInstanceState: Bundle?) {
        super.onViewCreated(view, savedInstanceState)

        binding.root.borderVisibilityChangedListener = OnBorderVisibilityChangedListener { top: Boolean, _: Boolean, _: Boolean, _: Boolean -> appActivity?.appBar?.setRaised(!top) }
    }

    override fun onActivityCreated(savedInstanceState: Bundle?) {
        super.onActivityCreated(savedInstanceState)

        val context = requireContext()

        viewModel.text.observe(viewLifecycleOwner) {
            when (it?.status) {
                Status.SUCCESS -> {
                    binding.textView.text = it.data
                }
                Status.ERROR -> {
                    binding.textView.text = it.data
                }
                Status.LOADING -> {
                }
            }
        }
        val useStrongBox = Build.VERSION.SDK_INT >= Build.VERSION_CODES.P &&
                context.packageManager.hasSystemFeature(PackageManager.FEATURE_STRONGBOX_KEYSTORE)
        if (savedInstanceState == null) {
            viewModel.invalidateAttestation(context, useStrongBox)
        }
    }

    fun showTrustedUnlockStatus(isGoogleRootCertificate: Boolean, attestation: Attestation) {
        if (isGoogleRootCertificate &&
                attestation.attestationSecurityLevel != Attestation.KM_SECURITY_LEVEL_SOFTWARE) {
            val rootOfTrust = attestation.teeEnforced.rootOfTrust
            if (rootOfTrust != null) {
                if (rootOfTrust.isDeviceLocked) appActivity?.appBar?.setSubtitle("Locked") else appActivity?.appBar?.setSubtitle("Unlocked")
                return
            }
        }
        appActivity?.appBar?.subtitle = "Unknown"
    }
}