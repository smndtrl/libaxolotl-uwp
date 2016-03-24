using libaxolotl.util;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Windows.Security.Cryptography;
using Windows.Security.Cryptography.Core;
using Windows.Storage.Streams;

namespace libaxolotl.fingerprint
{
    public class NumericFingerprintGenerator : FingerprintGenerator
    {

        private static readonly int VERSION = 0;

        private readonly long iterations;

        /**
         * Construct a fingerprint generator for 60 digit numerics.
         *
         * @param iterations The number of internal iterations to perform in the process of
         *                   generating a fingerprint. This needs to be constant, and synchronized
         *                   across all clients.
         *
         *                   The higher the iteration count, the higher the security level:
         *
         *                   - 1024 ~ 109.7 bits
         *                   - 1400 > 110 bits
         *                   - 5200 > 112 bits
         */
        public NumericFingerprintGenerator(long iterations)
        {
            this.iterations = iterations;
        }

        /**
         * Generate a scannable and displayble fingerprint.
         *
         * @param localStableIdentifier The client's "stable" identifier.
         * @param localIdentityKey The client's identity key.
         * @param remoteStableIdentifier The remote party's "stable" identifier.
         * @param remoteIdentityKey The remote party's identity key.
         * @return A unique fingerprint for this conversation.
         */
        public Fingerprint createFor(String localStableIdentifier, IdentityKey localIdentityKey, String remoteStableIdentifier, IdentityKey remoteIdentityKey)
        {
            DisplayableFingerprint displayableFingerprint = new DisplayableFingerprint(getDisplayStringFor(localStableIdentifier, localIdentityKey),
                                                                                       getDisplayStringFor(remoteStableIdentifier, remoteIdentityKey));

            ScannableFingerprint scannableFingerprint = new ScannableFingerprint(VERSION,
                                                                                 localStableIdentifier, localIdentityKey,
                                                                                 remoteStableIdentifier, remoteIdentityKey);

            return new Fingerprint(displayableFingerprint, scannableFingerprint);
        }

        private String getDisplayStringFor(String stableIdentifier, IdentityKey identityKey)
        {
            try
            {
                //TODO: Port Hash to C# - done;

                HashAlgorithmProvider algProvider = HashAlgorithmProvider.OpenAlgorithm(HashAlgorithmNames.Sha512);
                CryptographicHash hasher = algProvider.CreateHash();

                //MessageDigest digest = MessageDigest.getInstance("SHA-512");
                byte[] publicKey = identityKey.PublicKey.serialize();
                byte[] hash = ByteUtil.combine(ByteUtil.shortToByteArray(VERSION),
                                                           publicKey, Encoding.ASCII.GetBytes(stableIdentifier));

                for (int i = 0; i < iterations; i++)
                {
                    IBuffer data = CryptographicBuffer.CreateFromByteArray(hash);
                    hasher.Append(data);
                    CryptographicBuffer.CopyToByteArray(hasher.GetValueAndReset(), out hash);
                }

                return getEncodedChunk(hash, 0) +
                    getEncodedChunk(hash, 5) +
                    getEncodedChunk(hash, 10) +
                    getEncodedChunk(hash, 15) +
                    getEncodedChunk(hash, 20) +
                    getEncodedChunk(hash, 25);
            }
            catch (/*NoSuchAlgorithm*/Exception e)
            {
                throw e;
            }
        }

        private String getEncodedChunk(byte[] hash, int offset)
        {
            long chunk = ByteUtil.byteArray5ToLong(hash, offset) % 100000;
            return chunk.ToString().PadLeft(5, '0');
        }

    }

}
