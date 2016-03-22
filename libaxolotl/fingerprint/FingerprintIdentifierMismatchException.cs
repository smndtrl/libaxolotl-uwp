using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace libaxolotl.fingerprint
{
    public class FingerprintIdentifierMismatchException : Exception
    {
        private readonly String localIdentifier;
        private readonly String remoteIdentifier;
        private readonly String scannedLocalIdentifier;
        private readonly String scannedRemoteIdentifier;

        public FingerprintIdentifierMismatchException(String localIdentifier, String remoteIdentifier,
                                                      String scannedLocalIdentifier, String scannedRemoteIdentifier)
        {
            this.localIdentifier = localIdentifier;
            this.remoteIdentifier = remoteIdentifier;
            this.scannedLocalIdentifier = scannedLocalIdentifier;
            this.scannedRemoteIdentifier = scannedRemoteIdentifier;
        }

        public String getScannedRemoteIdentifier()
        {
            return scannedRemoteIdentifier;
        }

        public String getScannedLocalIdentifier()
        {
            return scannedLocalIdentifier;
        }

        public String getRemoteIdentifier()
        {
            return remoteIdentifier;
        }

        public String getLocalIdentifier()
        {
            return localIdentifier;
        }
    }
}
