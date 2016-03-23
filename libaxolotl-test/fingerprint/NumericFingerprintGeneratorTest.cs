using libaxolotl;
using libaxolotl.ecc;
using libaxolotl.fingerprint;
using Microsoft.VisualStudio.TestPlatform.UnitTestFramework;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace libaxolotl_test.fingerprint
{
    [TestClass]
    public class NumericFingerprintGeneratorTest
    {
        [TestMethod, TestCategory("libaxolotl")]
        public void testMatchingFingerprints()
        {
            ECKeyPair aliceKeyPair = Curve.generateKeyPair();
            ECKeyPair bobKeyPair = Curve.generateKeyPair();

            IdentityKey aliceIdentityKey = new IdentityKey(aliceKeyPair.getPublicKey());
            IdentityKey bobIdentityKey = new IdentityKey(bobKeyPair.getPublicKey());

            NumericFingerprintGenerator generator = new NumericFingerprintGenerator(1024);
            Fingerprint aliceFingerprint = generator.createFor("+14152222222", aliceIdentityKey,
                                                                "+14153333333", bobIdentityKey);

            Fingerprint bobFingerprint = generator.createFor("+14153333333", bobIdentityKey,
                                                            "+14152222222", aliceIdentityKey);

            Assert.AreEqual(aliceFingerprint.getDisplayableFingerprint().getDisplayText(), bobFingerprint.getDisplayableFingerprint().getDisplayText());

            Assert.IsTrue(aliceFingerprint.getScannableFingerprint().compareTo(bobFingerprint.getScannableFingerprint().getSerialized()));
            Assert.IsTrue(bobFingerprint.getScannableFingerprint().compareTo(aliceFingerprint.getScannableFingerprint().getSerialized()));

            Assert.AreEqual(aliceFingerprint.getDisplayableFingerprint().getDisplayText().Length, 60);
        }

        [TestMethod, TestCategory("libaxolotl")]
        public void testMismatchingFingerprints()
        {
            ECKeyPair aliceKeyPair = Curve.generateKeyPair();
            ECKeyPair bobKeyPair = Curve.generateKeyPair();
            ECKeyPair mitmKeyPair = Curve.generateKeyPair();

            IdentityKey aliceIdentityKey = new IdentityKey(aliceKeyPair.getPublicKey());
            IdentityKey bobIdentityKey = new IdentityKey(bobKeyPair.getPublicKey());
            IdentityKey mitmIdentityKey = new IdentityKey(mitmKeyPair.getPublicKey());

            NumericFingerprintGenerator generator = new NumericFingerprintGenerator(1024);
            Fingerprint aliceFingerprint = generator.createFor("+14152222222", aliceIdentityKey,
                                                                               "+14153333333", mitmIdentityKey);

            Fingerprint bobFingerprint = generator.createFor("+14153333333", bobIdentityKey,
                                                             "+14152222222", aliceIdentityKey);

            Assert.AreNotEqual(aliceFingerprint.getDisplayableFingerprint().getDisplayText(),
                          bobFingerprint.getDisplayableFingerprint().getDisplayText());

            Assert.IsFalse(aliceFingerprint.getScannableFingerprint().compareTo(bobFingerprint.getScannableFingerprint().getSerialized()));
            Assert.IsFalse(bobFingerprint.getScannableFingerprint().compareTo(aliceFingerprint.getScannableFingerprint().getSerialized()));
        }

        [TestMethod, TestCategory("libaxolotl")]
        public void testMismatchingIdentifiers()
        {
            ECKeyPair aliceKeyPair = Curve.generateKeyPair();
            ECKeyPair bobKeyPair = Curve.generateKeyPair();

            IdentityKey aliceIdentityKey = new IdentityKey(aliceKeyPair.getPublicKey());
            IdentityKey bobIdentityKey = new IdentityKey(bobKeyPair.getPublicKey());

            NumericFingerprintGenerator generator = new NumericFingerprintGenerator(1024);
            Fingerprint aliceFingerprint = generator.createFor("+141512222222", aliceIdentityKey,
                                                                               "+14153333333", bobIdentityKey);

            Fingerprint bobFingerprint = generator.createFor("+14153333333", bobIdentityKey,
                                                             "+14152222222", aliceIdentityKey);

            Assert.AreNotEqual(aliceFingerprint.getDisplayableFingerprint().getDisplayText(),
                          bobFingerprint.getDisplayableFingerprint().getDisplayText());

            try
            {
                aliceFingerprint.getScannableFingerprint().compareTo(bobFingerprint.getScannableFingerprint().getSerialized());
                throw new Exception("Should mismatch!");
            }
            catch (FingerprintIdentifierMismatchException e)
            {
                // good
            }

            try
            {
                bobFingerprint.getScannableFingerprint().compareTo(aliceFingerprint.getScannableFingerprint().getSerialized());
                throw new Exception("Should mismatch!");
            }
            catch (FingerprintIdentifierMismatchException e)
            {
                // good
            }
        }
    }
}
