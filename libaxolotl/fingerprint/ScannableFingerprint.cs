using System;

namespace libaxolotl.fingerprint
{
    public class ScannableFingerprint
    {
        //private readonly CombinedFingerprint combinedFingerprint;

        public ScannableFingerprint(int version,
                                    String localStableIdentifier, IdentityKey localIdentityKey,
                                    String remoteStableIdentifier, IdentityKey remoteIdentityKey)
        {
            //this.combinedFingerprint = CombinedFingerprint.newBuilder()
            //                                              .setVersion(version)
            //                                              .setLocalFingerprint(FingerprintData.newBuilder()
            //                                                                                  .setIdentifier(ByteString.copyFrom(localStableIdentifier.getBytes()))
            //                                                                                  .setPublicKey(ByteString.copyFrom(localIdentityKey.serialize())))
            //                                              .setRemoteFingerprint(FingerprintData.newBuilder()
            //                                                                                   .setIdentifier(ByteString.copyFrom(remoteStableIdentifier.getBytes()))
            //                                                                                   .setPublicKey(ByteString.copyFrom(remoteIdentityKey.serialize())))
            //                                              .build();
        }

        /**
         * @return A byte string to be displayed in a QR code.
         */
        public byte[] getSerialized()
        {
            throw new NotImplementedException();
            //return combinedFingerprint.toByteArray();
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
                //  CombinedFingerprint scannedFingerprint = CombinedFingerprint.parseFrom(scannedFingerprintData);

                //  if (!scannedFingerprint.hasRemoteFingerprint() || !scannedFingerprint.hasLocalFingerprint() ||
                //      !scannedFingerprint.hasVersion() || scannedFingerprint.getVersion() != combinedFingerprint.getVersion())
                //  {
                //    throw new FingerprintVersionMismatchException();
                //}

                //  if (!combinedFingerprint.getLocalFingerprint().getIdentifier().equals(scannedFingerprint.getRemoteFingerprint().getIdentifier()) ||
                //      !combinedFingerprint.getRemoteFingerprint().getIdentifier().equals(scannedFingerprint.getLocalFingerprint().getIdentifier()))
                //  {
                //    throw new FingerprintIdentifierMismatchException(new String(combinedFingerprint.getLocalFingerprint().getIdentifier().toByteArray()),
                //                                                     new String(combinedFingerprint.getRemoteFingerprint().getIdentifier().toByteArray()),
                //                                                     new String(scannedFingerprint.getLocalFingerprint().getIdentifier().toByteArray()),
                //                                                     new String(scannedFingerprint.getRemoteFingerprint().getIdentifier().toByteArray()));
                //  }

                //  return MessageDigest.isEqual(combinedFingerprint.getLocalFingerprint().toByteArray(), scannedFingerprint.getRemoteFingerprint().toByteArray()) &&
                //         MessageDigest.isEqual(combinedFingerprint.getRemoteFingerprint().toByteArray(), scannedFingerprint.getLocalFingerprint().toByteArray());
                //} catch (InvalidProtocolBufferException e) {
                //  throw new FingerprintParsingException(e);
                //}
            }
            catch
            { }

            throw new NotImplementedException();
        }
    }
 }