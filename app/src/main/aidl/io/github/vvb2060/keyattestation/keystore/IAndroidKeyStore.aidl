package io.github.vvb2060.keyattestation.keystore;

import android.hardware.security.keymint.DeviceInfo;
import android.hardware.security.keymint.RpcHardwareInfo;

interface IAndroidKeyStore {
    byte[] getCertificateChain(String alias);
    boolean containsAlias(String alias);
    void deleteAllEntry();
    void importKeyBox(String alias, boolean useStrongBox, in ParcelFileDescriptor pfd);
    byte[] generateKeyPair(String alias, String attestKeyAlias, boolean useStrongBox,
                           boolean includeProps, boolean uniqueIdIncluded, int idFlags,
                           boolean useSak);
    byte[] attestDeviceIds(int idFlags);
    void setRkpHostname(String hostname);
    String getRkpHostname();
    boolean canRemoteProvisioning(boolean useStrongBox);
    RpcHardwareInfo getHardwareInfo(boolean useStrongBox, out DeviceInfo deviceInfo);
    byte[] checkRemoteProvisioning(boolean useStrongBox);
}
