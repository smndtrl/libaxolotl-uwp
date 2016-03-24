using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace libaxolotl.fingerprint
{
    public class FingerprintParsingException : Exception
    {

        public FingerprintParsingException(Exception nested) : base(nested.Message)
        {
        }
    }
}
