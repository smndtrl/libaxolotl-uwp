using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace libaxolotl.fingerprint
{
    public class FingerprintVersionMismatchException : Exception
    {

        public FingerprintVersionMismatchException() : base()
        {
        }

        public FingerprintVersionMismatchException(Exception e) : base(e.Message)
        {
        }
    }

}
