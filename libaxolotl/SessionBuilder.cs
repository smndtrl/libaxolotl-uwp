/** 
 * Copyright (C) 2015 smndtrl
 * 
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

using libaxolotl.ecc;
using libaxolotl.exceptions;
using libaxolotl.protocol;
using libaxolotl.ratchet;
using libaxolotl.state;
using libaxolotl.util;
using Strilanc.Value;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace libaxolotl
{
    /**
 * SessionBuilder is responsible for setting up encrypted sessions.
 * Once a session has been established, {@link org.whispersystems.libaxolotl.SessionCipher}
 * can be used to encrypt/decrypt messages in that session.
 * <p>
 * Sessions are built from one of three different possible vectors:
 * <ol>
 *   <li>A {@link org.whispersystems.libaxolotl.state.PreKeyBundle} retrieved from a server.</li>
 *   <li>A {@link org.whispersystems.libaxolotl.protocol.PreKeyWhisperMessage} received from a client.</li>
 *   <li>A {@link org.whispersystems.libaxolotl.protocol.KeyExchangeMessage} sent to or received from a client.</li>
 * </ol>
 *
 * Sessions are constructed per recipientId + deviceId tuple.  Remote logical users are identified
 * by their recipientId, and each logical recipientId can have multiple physical devices.
 *
 * @author Moxie Marlinspike
 */
    public class SessionBuilder
    {

        private readonly SessionStore sessionStore;
        private readonly PreKeyStore preKeyStore;
        private readonly SignedPreKeyStore signedPreKeyStore;
        private readonly IdentityKeyStore identityKeyStore;
        private readonly AxolotlAddress remoteAddress;

        /**
         * Constructs a SessionBuilder.
         *
         * @param sessionStore The {@link org.whispersystems.libaxolotl.state.SessionStore} to store the constructed session in.
         * @param preKeyStore The {@link  org.whispersystems.libaxolotl.state.PreKeyStore} where the client's local {@link org.whispersystems.libaxolotl.state.PreKeyRecord}s are stored.
         * @param identityKeyStore The {@link org.whispersystems.libaxolotl.state.IdentityKeyStore} containing the client's identity key information.
         * @param remoteAddress The address of the remote user to build a session with.
         */
        public SessionBuilder(SessionStore sessionStore,
                              PreKeyStore preKeyStore,
                              SignedPreKeyStore signedPreKeyStore,
                              IdentityKeyStore identityKeyStore,
                              AxolotlAddress remoteAddress)
        {
            this.sessionStore = sessionStore;
            this.preKeyStore = preKeyStore;
            this.signedPreKeyStore = signedPreKeyStore;
            this.identityKeyStore = identityKeyStore;
            this.remoteAddress = remoteAddress;
        }

        /**
         * Constructs a SessionBuilder
         * @param store The {@link org.whispersystems.libaxolotl.state.AxolotlStore} to store all state information in.
         * @param remoteAddress The address of the remote user to build a session with.
         */
        public SessionBuilder(AxolotlStore store, AxolotlAddress remoteAddress)
            : this(store, store, store, store, remoteAddress)
        {
        }

        /**
         * Build a new session from a received {@link org.whispersystems.libaxolotl.protocol.PreKeyWhisperMessage}.
         *
         * After a session is constructed in this way, the embedded {@link org.whispersystems.libaxolotl.protocol.WhisperMessage}
         * can be decrypted.
         *
         * @param message The received {@link org.whispersystems.libaxolotl.protocol.PreKeyWhisperMessage}.
         * @throws org.whispersystems.libaxolotl.InvalidKeyIdException when there is no local
         *                                                             {@link org.whispersystems.libaxolotl.state.PreKeyRecord}
         *                                                             that corresponds to the PreKey ID in
         *                                                             the message.
         * @throws org.whispersystems.libaxolotl.InvalidKeyException when the message is formatted incorrectly.
         * @throws org.whispersystems.libaxolotl.UntrustedIdentityException when the {@link IdentityKey} of the sender is untrusted.
         */
        /*package*/
        internal May<uint>  process(SessionRecord sessionRecord, PreKeyWhisperMessage message)
        {
            IdentityKey theirIdentityKey = message.getIdentityKey();

            if (!identityKeyStore.IsTrustedIdentity(remoteAddress.Name, theirIdentityKey))
            {
                throw new UntrustedIdentityException(remoteAddress.Name, theirIdentityKey);
            }

            May<uint> unsignedPreKeyId = processV3(sessionRecord, message);
            identityKeyStore.SaveIdentity(remoteAddress.Name, theirIdentityKey);
            return unsignedPreKeyId;
        }

        private May<uint> processV3(SessionRecord sessionRecord, PreKeyWhisperMessage message)
        {

            if (sessionRecord.hasSessionState(message.getMessageVersion(), message.getBaseKey().serialize()))
            {
                //Log.w(TAG, "We've already setup a session for this V3 message, letting bundled message fall through...");
                return May<uint>.NoValue;
            }

            ECKeyPair ourSignedPreKey = signedPreKeyStore.LoadSignedPreKey(message.getSignedPreKeyId()).getKeyPair();

            BobAxolotlParameters.Builder parameters = BobAxolotlParameters.newBuilder();

            parameters.setTheirBaseKey(message.getBaseKey())
                      .setTheirIdentityKey(message.getIdentityKey())
                      .setOurIdentityKey(identityKeyStore.GetIdentityKeyPair())
                      .setOurSignedPreKey(ourSignedPreKey)
                      .setOurRatchetKey(ourSignedPreKey);

            if (message.getPreKeyId().HasValue)
            {
                parameters.setOurOneTimePreKey(new May<ECKeyPair>(preKeyStore.LoadPreKey(message.getPreKeyId().ForceGetValue()).getKeyPair()));
            }
            else
            {
                parameters.setOurOneTimePreKey(May<ECKeyPair>.NoValue);
            }

            if (!sessionRecord.isFresh()) sessionRecord.archiveCurrentState();

            RatchetingSession.initializeSession(sessionRecord.getSessionState(), parameters.create());

            sessionRecord.getSessionState().setLocalRegistrationId(identityKeyStore.GetLocalRegistrationId());
            sessionRecord.getSessionState().setRemoteRegistrationId(message.getRegistrationId());
            sessionRecord.getSessionState().setAliceBaseKey(message.getBaseKey().serialize());

            if (message.getPreKeyId().HasValue && message.getPreKeyId().ForceGetValue() != Medium.MAX_VALUE)
            {
                return message.getPreKeyId();
            }
            else
            {
                return May<uint>.NoValue;
            }
        }

    
        /**
         * Build a new session from a {@link org.whispersystems.libaxolotl.state.PreKeyBundle} retrieved from
         * a server.
         *
         * @param preKey A PreKey for the destination recipient, retrieved from a server.
         * @throws InvalidKeyException when the {@link org.whispersystems.libaxolotl.state.PreKeyBundle} is
         *                             badly formatted.
         * @throws org.whispersystems.libaxolotl.UntrustedIdentityException when the sender's
         *                                                                  {@link IdentityKey} is not
         *                                                                  trusted.
         */
        public void process(PreKeyBundle preKey)
        {
            lock (SessionCipher.SESSION_LOCK)
            {
                if (!identityKeyStore.IsTrustedIdentity(remoteAddress.Name, preKey.getIdentityKey()))
                {
                    throw new UntrustedIdentityException(remoteAddress.Name, preKey.getIdentityKey());
                }

                if (preKey.getSignedPreKey() != null &&
                    !Curve.verifySignature(preKey.getIdentityKey().PublicKey,
                                           preKey.getSignedPreKey().serialize(),
                                           preKey.getSignedPreKeySignature()))
                {
                    throw new InvalidKeyException("Invalid signature on device key!");
                }

                if (preKey.getSignedPreKey() == null)
                {
                    throw new InvalidKeyException("No signed prekey!");
                }
                
                SessionRecord sessionRecord = sessionStore.LoadSession(remoteAddress);
                ECKeyPair ourBaseKey = Curve.generateKeyPair();
                ECPublicKey theirSignedPreKey = preKey.getSignedPreKey();
                May<ECPublicKey> theirOneTimePreKey = (preKey == null) ? May<ECPublicKey>.NoValue : new May<ECPublicKey>(preKey.getPreKey());
                May<uint> theirOneTimePreKeyId = theirOneTimePreKey.HasValue ? new May<uint>(preKey.getPreKeyId()) :
                                                                                              May<uint>.NoValue;

                AliceAxolotlParameters.Builder parameters = AliceAxolotlParameters.newBuilder();

                parameters.setOurBaseKey(ourBaseKey)
                              .setOurIdentityKey(identityKeyStore.GetIdentityKeyPair())
                              .setTheirIdentityKey(preKey.getIdentityKey())
                              .setTheirSignedPreKey(theirSignedPreKey)
                              .setTheirRatchetKey(theirSignedPreKey)
                              .setTheirOneTimePreKey(theirOneTimePreKey);

                if (!sessionRecord.isFresh()) sessionRecord.archiveCurrentState();

                RatchetingSession.initializeSession(sessionRecord.getSessionState(), parameters.create());

                sessionRecord.getSessionState().setUnacknowledgedPreKeyMessage(theirOneTimePreKeyId, preKey.getSignedPreKeyId(), ourBaseKey.getPublicKey());
                sessionRecord.getSessionState().setLocalRegistrationId(identityKeyStore.GetLocalRegistrationId());
                sessionRecord.getSessionState().setRemoteRegistrationId(preKey.getRegistrationId());
                sessionRecord.getSessionState().setAliceBaseKey(ourBaseKey.getPublicKey().serialize());

                sessionStore.StoreSession(remoteAddress, sessionRecord);
                identityKeyStore.SaveIdentity(remoteAddress.Name, preKey.getIdentityKey());
            }
        }

        /**
         * Build a new session from a {@link org.whispersystems.libaxolotl.protocol.KeyExchangeMessage}
         * received from a remote client.
         *
         * @param message The received KeyExchangeMessage.
         * @return The KeyExchangeMessage to respond with, or null if no response is necessary.
         * @throws InvalidKeyException if the received KeyExchangeMessage is badly formatted.
         */
        public KeyExchangeMessage process(KeyExchangeMessage message)

        {
            lock (SessionCipher.SESSION_LOCK)
            {
                if (!identityKeyStore.IsTrustedIdentity(remoteAddress.Name, message.getIdentityKey()))
                {
                    throw new UntrustedIdentityException(remoteAddress.Name, message.getIdentityKey());
                }

                KeyExchangeMessage responseMessage = null;

                if (message.isInitiate()) responseMessage = processInitiate(message);
                else processResponse(message);

                return responseMessage;
            }
        }

        private KeyExchangeMessage processInitiate(KeyExchangeMessage message)
        {
            uint flags = KeyExchangeMessage.RESPONSE_FLAG;
            SessionRecord sessionRecord = sessionStore.LoadSession(remoteAddress);

            if (!Curve.verifySignature(message.getIdentityKey().PublicKey,
                                       message.getBaseKey().serialize(),
                                       message.getBaseKeySignature()))
            {
                throw new InvalidKeyException("Bad signature!");
            }

            SymmetricAxolotlParameters.Builder builder = SymmetricAxolotlParameters.newBuilder();

            if (!sessionRecord.getSessionState().hasPendingKeyExchange())
            {
                builder.setOurIdentityKey(identityKeyStore.GetIdentityKeyPair())
                       .setOurBaseKey(Curve.generateKeyPair())
                       .setOurRatchetKey(Curve.generateKeyPair());
            }
            else
            {
                builder.setOurIdentityKey(sessionRecord.getSessionState().getPendingKeyExchangeIdentityKey())
                       .setOurBaseKey(sessionRecord.getSessionState().getPendingKeyExchangeBaseKey())
                       .setOurRatchetKey(sessionRecord.getSessionState().getPendingKeyExchangeRatchetKey());
                flags |= KeyExchangeMessage.SIMULTAENOUS_INITIATE_FLAG;
            }

            builder.setTheirBaseKey(message.getBaseKey())
                   .setTheirRatchetKey(message.getRatchetKey())
                   .setTheirIdentityKey(message.getIdentityKey());

            SymmetricAxolotlParameters parameters = builder.create();

            if (!sessionRecord.isFresh()) sessionRecord.archiveCurrentState();

            RatchetingSession.initializeSession(sessionRecord.getSessionState(), parameters);

            sessionStore.StoreSession(remoteAddress, sessionRecord);
            identityKeyStore.SaveIdentity(remoteAddress.Name, message.getIdentityKey());

            byte[] baseKeySignature = Curve.calculateSignature(parameters.getOurIdentityKey().getPrivateKey(),
                                                               parameters.getOurBaseKey().getPublicKey().serialize());

            return new KeyExchangeMessage(sessionRecord.getSessionState().getSessionVersion(),
                                          message.getSequence(), flags,
                                          parameters.getOurBaseKey().getPublicKey(),
                                          baseKeySignature, parameters.getOurRatchetKey().getPublicKey(),
                                          parameters.getOurIdentityKey().getPublicKey());
        }

        private void processResponse(KeyExchangeMessage message)
        {
            SessionRecord sessionRecord = sessionStore.LoadSession(remoteAddress);
            SessionState sessionState = sessionRecord.getSessionState();
            bool hasPendingKeyExchange = sessionState.hasPendingKeyExchange();
            bool isSimultaneousInitiateResponse = message.isResponseForSimultaneousInitiate();

            if (!hasPendingKeyExchange || sessionState.getPendingKeyExchangeSequence() != message.getSequence())
            {
                //Log.w(TAG, "No matching sequence for response. Is simultaneous initiate response: " + isSimultaneousInitiateResponse);
                if (!isSimultaneousInitiateResponse) throw new StaleKeyExchangeException();
                else return;
            }

            SymmetricAxolotlParameters.Builder parameters = SymmetricAxolotlParameters.newBuilder();

            parameters.setOurBaseKey(sessionRecord.getSessionState().getPendingKeyExchangeBaseKey())
                      .setOurRatchetKey(sessionRecord.getSessionState().getPendingKeyExchangeRatchetKey())
                      .setOurIdentityKey(sessionRecord.getSessionState().getPendingKeyExchangeIdentityKey())
                      .setTheirBaseKey(message.getBaseKey())
                      .setTheirRatchetKey(message.getRatchetKey())
                      .setTheirIdentityKey(message.getIdentityKey());

            if (!sessionRecord.isFresh()) sessionRecord.archiveCurrentState();

            RatchetingSession.initializeSession(sessionRecord.getSessionState(), parameters.create());

            if (!Curve.verifySignature(message.getIdentityKey().PublicKey,
                                       message.getBaseKey().serialize(),
                                       message.getBaseKeySignature()))
            {
                throw new InvalidKeyException("Base key signature doesn't match!");
            }

            sessionStore.StoreSession(remoteAddress, sessionRecord);
            identityKeyStore.SaveIdentity(remoteAddress.Name, message.getIdentityKey());
        }

        /**
         * Initiate a new session by sending an initial KeyExchangeMessage to the recipient.
         *
         * @return the KeyExchangeMessage to deliver.
         */
        public KeyExchangeMessage process()
        {
            lock (SessionCipher.SESSION_LOCK)
            {
                try
                {
                    uint sequence = KeyHelper.getRandomSequence(65534) + 1;
                    uint flags = KeyExchangeMessage.INITIATE_FLAG;
                    ECKeyPair baseKey = Curve.generateKeyPair();
                    ECKeyPair ratchetKey = Curve.generateKeyPair();
                    IdentityKeyPair identityKey = identityKeyStore.GetIdentityKeyPair();
                    byte[] baseKeySignature = Curve.calculateSignature(identityKey.getPrivateKey(), baseKey.getPublicKey().serialize());
                    SessionRecord sessionRecord = sessionStore.LoadSession(remoteAddress);

                    sessionRecord.getSessionState().setPendingKeyExchange(sequence, baseKey, ratchetKey, identityKey);
                    sessionStore.StoreSession(remoteAddress, sessionRecord);

                    return new KeyExchangeMessage(CiphertextMessage.CURRENT_VERSION,
                                                    sequence, flags, baseKey.getPublicKey(), baseKeySignature,
                                                    ratchetKey.getPublicKey(), identityKey.getPublicKey());
                }
                catch (InvalidKeyException e)
                {
                    throw new Exception(e.Message);
                }
            }
        }


    }
}
