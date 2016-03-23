using Google.ProtocolBuffers;
using System;
using System.Linq;
using System.Text;
using static libaxolotl.fingerprint.FingerprintProtos;

namespace libaxolotl.fingerprint
{
    public class ScannableFingerprint
    {
        private readonly CombinedFingerprint combinedFingerprint;

        public ScannableFingerprint(int version,
                                    String localStableIdentifier, IdentityKey localIdentityKey,
                                    String remoteStableIdentifier, IdentityKey remoteIdentityKey)
        {
            this.combinedFingerprint = CombinedFingerprint.CreateBuilder()
                                                          .SetVersion((uint)version)
                                                          .SetLocalFingerprint(FingerprintData.CreateBuilder()
                                                                                              .SetIdentifier(ByteString.CopyFrom(Encoding.ASCII.GetBytes(localStableIdentifier)))
                                                                                              .SetPublicKey(ByteString.CopyFrom(localIdentityKey.serialize())))
                                                          .SetRemoteFingerprint(FingerprintData.CreateBuilder()
                                                                                               .SetIdentifier(ByteString.CopyFrom(Encoding.ASCII.GetBytes(remoteStableIdentifier)))
                                                                                               .SetPublicKey(ByteString.CopyFrom(remoteIdentityKey.serialize())))
                                                          .Build();
        }

        /**
         * @return A byte string to be displayed in a QR code.
         */
        public byte[] getSerialized()
        {
            return combinedFingerprint.ToByteArray();
        }

        /**
         * Compare a scanned QR code with what we expect.
         *
         * @param scannedFingerprintData The scanned data
         * @return True if matching, otehrwise false.
         * @throws FingerprintVersionMismatchException if the scanned fingerprint is the wrong version.
         * @throws FingerprintIdentifierMismatchException if the scanned fingerprint is for the wrong stable identifier.
         */
        public bool compareTo(byte[] scannedFingerprintData)
        {
            try
            {
                CombinedFingerprint scannedFingerprint = CombinedFingerprint.ParseFrom(scannedFingerprintData);

                if (!scannedFingerprint.HasRemoteFingerprint || !scannedFingerprint.HasLocalFingerprint ||
                    !scannedFingerprint.HasVersion || scannedFingerprint.Version != combinedFingerprint.Version)
                {
                    throw new FingerprintVersionMismatchException();
                }

                if (!combinedFingerprint.LocalFingerprint.Identifier.Equals(scannedFingerprint.RemoteFingerprint.Identifier) ||
                    !combinedFingerprint.RemoteFingerprint.Identifier.Equals(scannedFingerprint.LocalFingerprint.Identifier))
                {
                    throw new FingerprintIdentifierMismatchException(combinedFingerprint.LocalFingerprint.Identifier.ToBase64(),
                                                                     combinedFingerprint.RemoteFingerprint.Identifier.ToBase64(),
                                                                     scannedFingerprint.LocalFingerprint.Identifier.ToBase64(),
                                                                     scannedFingerprint.RemoteFingerprint.Identifier.ToBase64());
                }

                return combinedFingerprint.LocalFingerprint.ToByteArray().SequenceEqual(scannedFingerprint.RemoteFingerprint.ToByteArray()) &&
                       combinedFingerprint.RemoteFingerprint.ToByteArray().SequenceEqual(scannedFingerprint.LocalFingerprint.ToByteArray());
            }
            catch (InvalidProtocolBufferException e)
            {
                throw new FingerprintParsingException(e);
            }
        }
    }
 }