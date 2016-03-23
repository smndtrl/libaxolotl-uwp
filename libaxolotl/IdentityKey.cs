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
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace libaxolotl
{
    /**
     * A class for representing an identity key.
     * 
     * @author Moxie Marlinspike
     */

    public class IdentityKey
    {

        public ECPublicKey PublicKey { get; private set; }

        public IdentityKey(ECPublicKey publicKey)
        {
            this.PublicKey = publicKey;
        }

        public IdentityKey(byte[] bytes, int offset)
        {
            this.PublicKey = Curve.decodePoint(bytes, offset);
        }
        public byte[] serialize()
        {
            return PublicKey.serialize();
        }

        public String getFingerprint()
        {
            return PublicKey.serialize().ToString(); //Hex
        }

        public override bool Equals(Object other)
        {
            if (other == null) return false;
            if (!(other is IdentityKey)) return false;

            return PublicKey.Equals(((IdentityKey)other).PublicKey);
        }


        public override int GetHashCode()
        {
            return PublicKey.GetHashCode();
        }
    }
}
