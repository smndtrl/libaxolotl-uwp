using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace libaxolotl.fingerprint
{
    public class DisplayableFingerprint
    {

        private readonly String localFingerprint;
        private readonly String remoteFingerprint;

        public DisplayableFingerprint(String localFingerprint, String remoteFingerprint)
        {
            this.localFingerprint = localFingerprint;
            this.remoteFingerprint = remoteFingerprint;
        }

        public String getDisplayText()
        {
            if (localFingerprint.CompareTo(remoteFingerprint) <= 0)
            {
                return localFingerprint + remoteFingerprint;
            }
            else {
                return remoteFingerprint + localFingerprint;
            }
        }
    }
}
