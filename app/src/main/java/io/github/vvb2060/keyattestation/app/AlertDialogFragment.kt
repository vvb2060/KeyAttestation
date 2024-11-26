package io.github.vvb2060.keyattestation.app

import android.app.Dialog
import android.content.Context
import android.content.DialogInterface
import android.content.Intent
import android.os.Bundle
import android.os.Parcel
import android.os.Parcelable
import android.text.method.LinkMovementMethod
import android.widget.Button
import android.widget.TextView
import androidx.appcompat.app.AlertDialog
import androidx.fragment.app.DialogFragment
import androidx.fragment.app.FragmentManager

open class AlertDialogFragment : DialogFragment() {

    fun show(fragmentManager: FragmentManager) {
        if (fragmentManager.isStateSaved) return
        show(fragmentManager, javaClass.simpleName)
    }

    open fun onCreateAlertDialogBuilder(context: Context): AlertDialog.Builder {
        return AlertDialog.Builder(context)
    }

    override fun onCreateDialog(savedInstanceState: Bundle?): Dialog {
        val context = requireContext()
        val builder = onCreateAlertDialogBuilder(context)
        onBuildAlertDialog(builder, savedInstanceState)
        val dialog = builder.create()
        dialog.setOnShowListener { onShow(dialog) }
        onAlertDialogCreated(dialog, savedInstanceState)
        return dialog
    }

    open fun onBuildAlertDialog(builder: AlertDialog.Builder, savedInstanceState: Bundle?) {
        val args = requireArguments()
        if (args.containsKey(INTERNAL_BUILDER_ARGS)) {
            val dialogBuilder: Builder = args.getParcelable(INTERNAL_BUILDER_ARGS)!!
            builder.setTitle(dialogBuilder.title)
            builder.setMessage(dialogBuilder.message)
            if (dialogBuilder.positiveButtonText != null) {
                builder.setPositiveButton(dialogBuilder.positiveButtonText) { _: DialogInterface?, _: Int -> launchIntent(dialogBuilder.positiveButtonIntent) }
            }
            if (dialogBuilder.negativeButtonText != null) {
                builder.setNegativeButton(dialogBuilder.negativeButtonText) { _: DialogInterface?, _: Int -> launchIntent(dialogBuilder.negativeButtonIntent) }
            }
            if (dialogBuilder.neutralButtonText != null) {
                builder.setNeutralButton(dialogBuilder.neutralButtonText) { _: DialogInterface?, _: Int -> launchIntent(dialogBuilder.neutralButtonIntent) }
            }
        }
    }

    open fun onAlertDialogCreated(dialog: AlertDialog, savedInstanceState: Bundle?) {}

    open fun onShow(dialog: AlertDialog) {
        dialog.findViewById<TextView>(android.R.id.message)?.movementMethod = LinkMovementMethod.getInstance()
    }

    override fun getDialog(): AlertDialog? {
        return super.getDialog() as AlertDialog?
    }

    open fun getButton(whichButton: Int): Button? {
        return dialog?.getButton(whichButton)
    }

    private fun launchIntent(intent: Intent?) {
        if (intent != null) {
            //Do nothing.
        }
    }

    class Builder(private val context: Context?) : Parcelable {

        var title: CharSequence? = null
            private set

        var message: CharSequence? = null
            private set

        var positiveButtonText: CharSequence? = null
            private set

        var negativeButtonText: CharSequence? = null
            private set

        var neutralButtonText: CharSequence? = null
            private set

        var positiveButtonIntent: Intent? = null
            private set

        var negativeButtonIntent: Intent? = null
            private set

        var neutralButtonIntent: Intent? = null
            private set

        private constructor(`in`: Parcel) : this(null) {
            title = `in`.readString()
            message = `in`.readString()
            positiveButtonText = `in`.readString()
            negativeButtonText = `in`.readString()
            neutralButtonText = `in`.readString()
            positiveButtonIntent = `in`.readParcelable(Intent::class.java.classLoader)
            negativeButtonIntent = `in`.readParcelable(Intent::class.java.classLoader)
            neutralButtonIntent = `in`.readParcelable(Intent::class.java.classLoader)
        }

        fun title(title: CharSequence?) = apply { this.title = title }

        fun title(title: Int) = title(context!!.getString(title))

        fun message(message: CharSequence?) = apply { this.message = message }

        fun message(message: Int) = message(context!!.getString(message))

        fun positiveButton(text: CharSequence?, intent: Intent? = null) = apply {
            positiveButtonText = text
            positiveButtonIntent = intent
        }

        fun positiveButton(text: Int, intent: Intent? = null) = positiveButton(context!!.getString(text), intent)

        fun negativeButton(text: CharSequence?, intent: Intent? = null) = apply {
            negativeButtonText = text
            negativeButtonIntent = intent
        }

        fun negativeButton(text: Int, intent: Intent? = null) = negativeButton(context!!.getString(text), intent)

        fun neutralButton(text: CharSequence?, intent: Intent? = null) = apply {
            neutralButtonText = text
            neutralButtonIntent = intent
        }

        fun neutralButton(text: Int, intent: Intent? = null) = neutralButton(context!!.getString(text), intent)

        fun build(): AlertDialogFragment {
            val fragment = AlertDialogFragment()
            val args = Bundle()
            args.putParcelable(INTERNAL_BUILDER_ARGS, this)
            fragment.arguments = args
            return fragment
        }

        override fun describeContents(): Int {
            return 0
        }

        override fun writeToParcel(dest: Parcel, flags: Int) {
            dest.writeString(title?.toString())
            dest.writeString(message?.toString())
            dest.writeString(positiveButtonText?.toString())
            dest.writeString(negativeButtonText?.toString())
            dest.writeString(neutralButtonText?.toString())
            dest.writeParcelable(positiveButtonIntent, flags)
            dest.writeParcelable(negativeButtonIntent, flags)
            dest.writeParcelable(neutralButtonIntent, flags)
        }

        companion object {

            @JvmField
            val CREATOR: Parcelable.Creator<Builder> = object : Parcelable.Creator<Builder> {
                override fun createFromParcel(`in`: Parcel): Builder {
                    return Builder(`in`)
                }

                override fun newArray(size: Int): Array<Builder?> {
                    return arrayOfNulls(size)
                }
            }
        }
    }

    companion object {
        private val INTERNAL_BUILDER_ARGS = AlertDialogFragment::class.java.name + ".BUILDER_ARGS"
    }
}
