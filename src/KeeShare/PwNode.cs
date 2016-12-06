/*
 * KeeShare - Password sharing Plugin for KeePass
 * (C) Copyright 2011-2015 HicknHack Software GmbH
 *
 * The original code can be found at:
 *     https://github.com/hicknhack-software/KeeShare
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.

 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 */


using KeePassLib;
using KeePassLib.Security;
using System.Diagnostics;

namespace KeeShare
{
    public static class PwNode
    {
        /// <summary>
		/// creates a new ProxyNode for the specified user. This Proxy can be used to mark a
		/// PwGroup as "shared" to this user.
		/// </summary>
		/// <param name="name">oldUserName you want to have a proxyNode of</param>
		/// <returns>PwEntry ProxyNode of the specified user</returns>
		public static PwEntry CreateProxyNode(PwEntry rootNode)
        {
            Debug.Assert(rootNode != null, "CreateProxy got rootNode==null!");
                      
            string uuid = rootNode.Strings.Exists(KeeShare.UuidLinkField) ? rootNode.Strings.ReadSafe(KeeShare.UuidLinkField) : rootNode.Uuid.ToHexString(); 
            PwEntry proxy = rootNode.CloneDeep();
            proxy.SetUuid(new PwUuid(true), false);

            Debug.Assert(KeeShare.UuidLinkField != "", "CreateProxy has an empty linkIdentifier!");

            proxy.Strings.Set(KeeShare.UuidLinkField, new ProtectedString(true, uuid));

            Debug.Assert(proxy != null, "CreateProxy would return null!");

            return proxy;
        }
    }
}
