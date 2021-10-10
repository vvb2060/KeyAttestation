Android Key Attestation Sample App
==============================

This sample illustrates how to use the [Bouncy Castle ASN.1][1] parser to extract information
from an Android attestation data structure to verify that a key pair has been
generated in an Android device. This sample demonstrates how to generate and verify a certificate on a device.

[1]: https://www.bouncycastle.org/


Note that this sample demonstrates the verification of a certificate on the Android framework and not
on a server. Although can test the certificate and extensions directly
on a device, it is safer to run these checks on a separate server you can trust.

Getting Started
---------------

This sample uses the Gradle build system. To build this project, use the
`gradlew aR` command or use "Open Project" in Android Studio.


License
-------

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
