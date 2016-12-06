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


using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using KeePass;
using KeePass.Resources;
using KeePassLib;
using KeePassLib.Collections;
using KeePassLib.Cryptography.PasswordGenerator;
using KeePassLib.Security;

namespace KeeShare
{
	public class TreeManager
	{
		//the last element we modified
		public static PwEntry pe_lastModedEntry = null;

        public PwDatabase Database { get { return m_database; } }

		private PwDatabase m_database;
	
		/// <summary>
		/// initializes the Usermanager.
		/// for now it only creates the relevant PwGroups if they are not existing yet.
		/// </summary>
		public void Initialize(PwDatabase database)
		{
			Debug.Assert( null != database );
			m_database = database;

            //====================== autocreating the neccassary groups ==================================
            m_database.GetUsersGroup();
            m_database.GetGroupsGroup();
		}

        /// <summary>
		/// Updates the relevant references! This function should be called after every change we made
		/// to the database from the outside! Otherwise we could not ensure a consistent database
		/// </summary>
		/// <param name="database">The database where you made changes.</param>
		/// <returns>True if the function has made any changes to the actual database.</returns>
		public Changes CorrectStructure()
        {
            Changes changes = Changes.None;
            //set active database
            Debug.Assert(m_database != null);
            if (m_database == null)
            {
                return changes;
            }
            //it would be better to check if copyDb is opened, but this is currently restricted
            //by the effort needed to invest into the tests to keep everything working
            changes |= EnsureRecycleBin();
            //run all necessary tests - keep order!
            changes |= RemoveDuplicateProxies();
            changes |= FixSharingNodesForAllUsers();
            changes |= RemoveBrokenProxies();
            changes |= FixHomeFolders();
            changes |= EnsureUsersProxiesInUsersGroup();
            changes |= ConvertCopiedPasswordsToPasswordProxies();
            changes |= CheckReferences();
            return changes;
        }

        private ProtectedString CreatePassword()
		{
			ProtectedString pw = new ProtectedString();
			PwProfile pf = new PwProfile();
			pf.GeneratorType = PasswordGeneratorType.Pattern;
			//use 256bit Hex-Key-Profile
			pf.Pattern = "h{64}";
			CustomPwGeneratorPool pwGenPool = new CustomPwGeneratorPool();
			PwgError perr = PwGenerator.Generate(out pw, pf, null, pwGenPool);
			if (perr != PwgError.Success)
			{
				throw new Exception("Error while creating new password!");
			}
			return pw;
		}

		private PwEntry CreateUserNode(string name)
		{
			if (string.IsNullOrEmpty(name))
			{
                throw new ArgumentException("name cannot be null or empty");
			}
			// TODO: Remove magic strings - these are propably defined in KeePass
			PwEntry entry = new PwEntry(true, true);
			entry.AddTag("user");
			entry.Strings.Set(KeeShare.TitleField, new ProtectedString(true, name));
			//the rootNode links against itself
			entry.Strings.Set(KeeShare.UuidLinkField, new ProtectedString(true, entry.Uuid.ToHexString()));
			//create the key which will be used to encrypt the delta-containers
			entry.Strings.Set(KeeShare.PasswordField, CreatePassword());
			entry.IconId = PwIcon.UserKey;
			return entry;
		}

		/// <summary>
		/// The <c>CreateNewUser</c> function creates a new user you 
		/// later can share passwords with.
		/// This includes a proxy in the UsersGroupName group and also
		/// creates a new user-specific group in the tree UsersGroupName
		/// </summary>
		/// <param name="name">oldUserName of the new user</param>
		/// <returns>True if all is done properly! False otherwise!</returns>
		protected Changes CreateNewUser(string name, PwGroup useAsHome = null)
		{
			PwEntry newUser = CreateUserNode(name);
			PwGroup newUserGroup = useAsHome;
			if( newUserGroup == null )
			{   //create a new home for that user
				newUserGroup = m_database.GetUserHomeFor( newUser, true );
			}
			else
			{
				newUserGroup.IconId = PwIcon.UserKey;
				newUserGroup.Notes += newUser.Uuid.ToHexString();
			}

			//put the userRootNode into his homefolder
			newUser.SetParent(newUserGroup);
			//due to better userHandling while dragNdrop we create a proxyNode in the usersGroup
			PwEntry proxy = PwNode.CreateProxyNode( newUser );
			proxy.SetParent(m_database.GetUsersGroup());
			return Changes.GroupCreated | Changes.EntryCreated;
		}

		

		/// <summary>
		/// The <c>DeleteUser</c> function deletes a user created by psdShare.
		/// It also removes all entries in his folder and all occurrences of
		/// the specified user in the KeeShare-groups. So after deleting a
		/// user all information about what you shared with that user are
		/// lost.
		/// </summary>
		/// <param name="root">rootNode of the user we want to delete</param>
		protected void DeleteUser(PwEntry root)
		{
			//userspecific group should exist so we have to try to delete it
			PwGroup theUsersGroup = m_database.GetUserHomeFor(root, false );
			if( null != theUsersGroup ) {
				theUsersGroup.DeleteFrom(m_database.GetUsersGroup(), m_database);
			}
			//find all occurrences of the user in the entire tree an remove them
			//that automatically includes all shares
			RemoveBrokenProxies();
		}

		class PwProxyComparer : IComparer<PwEntry>
		{
			public int Compare(PwEntry pe1, PwEntry pe2)
			{
				string sGroup1 = pe1.ParentGroup.Name;
				string sGroup2 = pe2.ParentGroup.Name;
				if (0 > sGroup1.CompareTo(sGroup2))
				{
					return -1;
				}
				if (0 == sGroup1.CompareTo(sGroup2))
				{
					string sLink1 = pe1.Strings.ReadSafe(KeeShare.UuidLinkField);
					string sLink2 = pe2.Strings.ReadSafe(KeeShare.UuidLinkField);
					return sLink1.CompareTo(sLink2);
				}
				return 1;
			}
		}

		/// <summary>
		/// Finds and removes duplicate proxy entry in a PwGroup. (ca happen if the user shares 
		/// a folder more than once)
		/// </summary>
		/// <returns>True if made changes.</returns>
		private Changes RemoveDuplicateProxies()
		{
			PwObjectList<PwEntry> allProxies = m_database.GetAllProxyNodes();
			allProxies.Sort(new PwProxyComparer());
			PwEntry lastEntry = null;
			Changes changeFlag = Changes.None;
			foreach( PwEntry proxy in allProxies )
			{
				//we only have to compare the last and the actual pwEntry because they are sorted alphabetically
				if( AreEqualProxies( proxy, lastEntry ) )
				{
                    proxy.DeleteFrom(proxy.ParentGroup);
					changeFlag |= Changes.EntryDeleted;
				}
				lastEntry = proxy;
			}
			return changeFlag;
		}

		
		/// <summary>
		/// The <c>ShareGroupWithUser</c> function adds an user-proxy to the group group.
		/// This userentry specifies the user how should become access to the group group.
		/// </summary>
		/// <param name="group">The group we want to share.</param>
		/// <param name="root">userRootNode of the user we want to share the group with.</param>
		private void ShareGroupWithUser(PwGroup group, PwEntry root)
		{
			//if (!UserExists(name)) return;
			//check if group is shared allready
			if (GroupIsSharedToUser(group, root))
			{
				return;
			}
			PwEntry proxyNode = PwNode.CreateProxyNode( root );
			if (proxyNode != null)
			{
				proxyNode.SetParent(group);
			}
		}

		/// <summary>
		/// Checks if a folder is allready shared to  user.
		/// </summary>
		/// <param name="group">The group we want to be checked</param>
		/// <param name="root">The rootNode of the user of whom we want to test shared-status</param>
		/// <returns></returns>
		private bool GroupIsSharedToUser(PwGroup group, PwEntry root)
		{
			PwObjectList<PwEntry> entryList = group.GetEntries( false );
			foreach( PwEntry pe in entryList )
			{
				if (pe.Strings.ReadSafe(KeeShare.UuidLinkField) == root.Uuid.ToHexString())
				{
					return true;
				}
			}
			return false;
		}

 
        private Changes FixSharingNodesFor(PwEntry userNode)
        {
            PwGroup userHome = m_database.GetUserHomeFor(userNode, false);
            PwGroup usersGroup = m_database.GetUsersGroup();
            PwGroup recycleBin = m_database.RootGroup.FindGroup(m_database.RecycleBinUuid, false);
            if (m_database.RecycleBinEnabled && userNode.IsInsideParent(recycleBin))
            {
                return RemoveDeletedSharingNodes(userNode, userHome, usersGroup);
            }
            if (userNode.ParentGroup.IsHome() && !userNode.IsInsideParent(usersGroup))
            {
                return RestoreMovedUsersHome(userNode, userHome, usersGroup);
            }
            if (userNode.ParentGroup != userHome)
            {
                return RestoreMovedUserNode(userNode, userHome, usersGroup);
            }
            return EnsureMatchingNamingAndIcons(userNode, userHome, usersGroup);
        }

        private Changes RemoveDeletedSharingNodes(PwEntry userNode, PwGroup userHome, PwGroup usersGroup)
        {
            PwGroup recycleBin = m_database.RootGroup.FindGroup(m_database.RecycleBinUuid, false);
            Debug.Assert(userNode.IsInsideParent(recycleBin));
            //we delete the user completely
            userNode.DeleteFrom(userNode.ParentGroup, m_database);

            RemoveBrokenProxies();

            //if only the rootNode was moved to trash, we have to delete the users Home too!
            if (null != userHome)
            {
                userHome.DeleteFrom(usersGroup, m_database);
            }
            return Changes.GroupDeleted | Changes.EntryDeleted;
        }

        private Changes RestoreMovedUsersHome(PwEntry userNode, PwGroup userHome, PwGroup usersGroup)
        {
            //the complete homeFolder was moved to share another folder
            PwGroup group = userNode.ParentGroup;
            PwGroup parent = group.ParentGroup;
            group.MoveToParent(usersGroup);
            ShareGroupWithUser(parent, userNode);
            return Changes.GroupMoved;
        }

        private Changes RestoreMovedUserNode(PwEntry userNode, PwGroup userHome, PwGroup usersGroup)
        {
            //only the userNode was moved..
            //are we located anywhere in the "users"group => here we have to be careful!
            if (userNode.IsInsideParent(usersGroup))
            {
                //do we have a applicable homeFolder?
                if (null != userHome)
                {
                    //then we should only move back!
                    userNode.ParentGroup.Entries.Remove(userNode);
                    userNode.SetParent(userHome);
                    //and we are done here...
                    return Changes.EntryMoved;
                }
            }
            else
            {
                //else userNode was moved intentionally to share a folder, so move the rootNode back
                //and create a proxy at the new location
                PwGroup parentGroup = userNode.ParentGroup;
                parentGroup.Entries.Remove(userNode);
                //ensure that the original rootNode is located in his homefolder
                //move the original userRootNode back to his homefolder
                userNode.SetParent(m_database.GetUserHomeFor(userNode));

                //create proxyNode in the folder
                if (!GroupIsSharedToUser(parentGroup, userNode))
                {
                    PwEntry proxy = PwNode.CreateProxyNode(userNode);
                    proxy.SetParent(parentGroup);
                    return Changes.EntryMoved | Changes.EntryCreated;
                }
                return Changes.EntryMoved;
            }
            return Changes.None;
        }

        private Changes EnsureMatchingNamingAndIcons(PwEntry userNode, PwGroup userHome, PwGroup usersGroup)
        {
            string userName = userNode.Strings.ReadSafe(KeeShare.TitleField);
            //we are located in our home => check for new names.. and icons
            if (userNode.ParentGroup.Name == userNode.Strings.ReadSafe(KeeShare.TitleField) && userNode.IconId == userNode.ParentGroup.IconId)
            {
                return Changes.None;
            }
            if (userNode.LastModificationTime.Ticks >= userNode.ParentGroup.LastModificationTime.Ticks)
            {
                //if last change was in the rootNode the group has to become the new name
                PwObjectList<PwEntry> history = userNode.History;
                Changes changeFlags = Changes.None;
                string lastName = null;
                if (history.UCount > 0)
                {
                    lastName = history.GetAt(history.UCount - 1u).Strings.ReadSafe(KeeShare.TitleField);
                }
                if (lastName != userName && lastName == userNode.ParentGroup.Name)
                {
                    userNode.ParentGroup.Name = userName;
                    changeFlags |= Changes.GroupChanged;
                }
                if (userNode.IconId != userNode.ParentGroup.IconId)
                {
                    userNode.ParentGroup.IconId = userNode.IconId;
                    changeFlags |= Changes.GroupChanged;
                }
                return changeFlags;
            }
                
            //otherwise the name of the group was the actual name
            userName = userNode.ParentGroup.Name;
            userNode.CreateBackup(m_database);
            userNode.Strings.Set(KeeShare.TitleField, new ProtectedString(false, userName));
            //icons should also be the same!
            userNode.IconId = userNode.ParentGroup.IconId;
            userNode.Touch(true, false);
            return Changes.GroupChanged;
        }
        

		/// <summary>
		/// Ensures the all rootNodes for the userEntries are located in the
		/// usersGroup.
		/// </summary>
		private Changes FixSharingNodesForAllUsers()
		{
			PwObjectList<PwEntry> userNodes = m_database.GetAllUserNodes();
            Changes changeFlag = Changes.None;
			foreach (PwEntry userNode in userNodes )
			{
                changeFlag |= FixSharingNodesFor(userNode);
			}
			return changeFlag;
		}

        private Changes FixHomeFolders()
        {
            //====================================
            //maybe we have some emptyFolders => new homefolders!
            //we can use the same loop to test for illegal shares of
            //foreign homes. that means, a foreign proxy is located
            //in a users homefolder.
            PwGroup usersGroup = m_database.GetUsersGroup();
            PwObjectList<PwGroup> allHomes = usersGroup.GetGroups(false);
            PwObjectList<PwGroup> foreignHomes = new PwObjectList<PwGroup>();
            PwObjectList<PwGroup> emptyHomes = new PwObjectList<PwGroup>();
            foreach (PwGroup home in allHomes)
            {
                //we remember the empty folders, so we can later make them new users
                if (home.Entries.UCount == 0)
                {
                    emptyHomes.Add(home);
                }
                //if we have more than 1 entry in a homegroup we have to check for
                //possible foreign shares
                if (home.Entries.UCount > 1)
                {
                    List<PwEntry> entries = home.GetEntries(false).CloneShallowToList();
                    foreach (PwEntry entry in entries)
                    {
                        //is it a userPorxy or a pwdProxy?
                        //the first we have to remove but the second one
                        //is a note that we want to share a pwd with this user, 
                        //so we don't touch it!
                        if (m_database.IsUserProxy(entry))
                        {
                            entry.DeleteFrom(home, m_database);
                        }
                    }
                }
                //and maybe we have a foreign home in our homefolder (to share it..)
                //so we have to fix that too.
                foreach (PwGroup foreignHome in home.GetGroups(true))
                {
                    if (foreignHome.IsHome())
                    {
                        foreignHomes.Add(foreignHome);
                    }
                }
            }
            Changes changeFlag = Changes.None;
            foreach (PwGroup home in emptyHomes)
            {
                string userName = home.Name;

                try
                {
                    changeFlag |= CreateNewUser(userName, home);
                }
                catch (Exception)
                {
                    // WTF: Why?
                    //should throw the exception and later inform the user...
                }
            }
            foreach (PwGroup home in foreignHomes)
            {
                home.MoveToParent(m_database.GetUsersGroup());
                changeFlag |= Changes.GroupMoved;
            }
            return changeFlag;
        }

        private Changes EnsureUsersProxiesInUsersGroup()
        {
            PwGroup usersGroup = m_database.GetUsersGroup();
            PwObjectList<PwEntry> allUsers = m_database.GetAllUserNodes();
            PwObjectList<PwEntry> allUserGroupProxies = new PwObjectList<PwEntry>();
            HashSet<string> proxyIds = new HashSet<string>();

            //fill the allUserGroupProxyList with relevant entries
            foreach (PwEntry entry in usersGroup.GetEntries(false))
            {
                if (entry.IsProxyNode())
                {
                    allUserGroupProxies.Add(entry);
                    proxyIds.Add(entry.Strings.ReadSafe(KeeShare.UuidLinkField));
                }
            }

            //compare the numbers of proxyNodes in the usersGroup and the entries in the allUsers list
            //if they are equal all relevant proxies exist because we checked there consistence before
            // and we are done here
            Changes changeFlag = Changes.None;
            if (allUsers.UCount != allUserGroupProxies.UCount)
            {
                foreach (PwEntry rootNode in allUsers)
                {
                    if (!proxyIds.Contains(rootNode.Uuid.ToHexString()))
                    {
                        PwEntry proxy = PwNode.CreateProxyNode(rootNode);
                        proxy.SetParent(usersGroup);
                        changeFlag |= Changes.EntryCreated;
                    }
                }
            }
            return changeFlag;
        }

		/// <summary>
		/// The <c>RemoveBrokenProxies</c> function finds all proxies which have no valid
		/// UserRootNode or normal PwEntry as target and deletes them.
		/// </summary>
		/// <returns><c>ChangeFlags</c>It will set the ChangeFlags.CommonChange-flag if this function has made changes in the datastructure.
		/// Should be used to triger an UIupdate if you want to show the changes.</returns>
		private Changes RemoveBrokenProxies()
		{
			HashSet<string> uids = new HashSet<string>();
			//create list for the uuids because this way we can easily find a stringValue
			foreach( PwEntry target in m_database.GetAllProxyTargets( ) )
			{
				uids.Add( target.Uuid.ToHexString() );
			}

			Changes changeFlag = Changes.None;
			foreach( PwEntry proxy in m_database.GetAllProxyNodes() )
			{
				if( !uids.Contains( proxy.Strings.ReadSafe(KeeShare.UuidLinkField ) ) )
				{
                    //remove all brokenProxies because without their rootNode_X they are useless ..
                    proxy.DeleteFrom(proxy.ParentGroup, m_database);
					changeFlag |= Changes.EntryDeleted;
				}
			}

			return changeFlag;
		}

	

		/// <summary>
		/// Checks if a PwEntry was copied into the "Users"- or "Groups"-folder.
		/// If so, we should brand it as a proxy
		/// </summary>
		/// <returns>True if there are made any changes to the dataStructure</returns>
		private Changes ConvertCopiedPasswordsToPasswordProxies()
		{
			Changes changeFlag = Changes.None;
            var usersGroup = m_database.GetUsersGroup();
            var userGroupsGroup = m_database.GetGroupsGroup();
			var potentialProxyNodes = (usersGroup.GetEntries( true ).Union( userGroupsGroup.GetEntries( true ) ))
                .Where( e => ! e.IsUserNode() && ! e.IsProxyNode() )
                .ToDictionary(e => e.Uuid);

            var potentialProxyRoots = m_database.RootGroup.GetEntries(true)
                .Where(e => !e.IsUserNode()
                            && !e.IsProxyNode()
                            && !e.IsInsideParent(usersGroup)
                            && !e.IsInsideParent(userGroupsGroup)
                            && !potentialProxyNodes.ContainsKey(e.Uuid))
                .ToList();
             

			//allPws shouldn't hold entries from inside of the usersGroup because we want
			//to use them as pwdRoots and in that case we would create a inconsistent state
			foreach( var potentialProxy in potentialProxyNodes.Values)
			{
                PwEntry potentialRoot = null;
    			//find the most actual root in the possilbe rootNodes and use the Uuid from that root
				foreach ( PwEntry entry in potentialProxyRoots)
				{
					if(potentialProxy.IsSimilarTo(entry, false)
                        && (potentialRoot == null || potentialRoot.LastModificationTime.Ticks > entry.LastModificationTime.Ticks))
					{
                        potentialRoot = entry;
					}
				}
				if( potentialRoot != null )
				{
                    potentialProxy.MakeToProxyOf(potentialRoot);
					potentialProxy.Touch( true );
					changeFlag |= Changes.EntryConverted;
				}
			}
			return changeFlag;
		}


		/// <summary>
		/// Checks if two proxies have the same RootNode.
		/// </summary>
		/// <param name="proxy1">first proxy</param>
		/// <param name="proxy2">second proxy</param>
		/// <returns>True if both entries are proxies which are linked to the same root.</returns>
		private bool AreEqualProxies(PwEntry proxy1, PwEntry proxy2)
		{
			//proxies are equal if they have the same origParent AND are same proxy types AND if the link to the same rootNode_X
			return proxy1 != null
				&& proxy2 != null
				&& proxy1.ParentGroup == proxy2.ParentGroup
				&& proxy1.ProxyTargetIdentifier() == proxy2.ProxyTargetIdentifier();
		}

		/// <summary>
		/// The function checks if thelast made change has to be propageted to
		/// some referenced PwEntries
		/// </summary>
		/// <returns>True if the function has made changes to the database.</returns>
		private Changes CheckReferences()
		{
			PwEntry lastModifiedEntry = GetLastModifiedEntry();
			//if there are no changes, then we have nothing to do
			if (lastModifiedEntry == null)
			{
				return Changes.None;
			}
			//was it a proxy or not?
			Changes changeFlag = Changes.None;
			if( lastModifiedEntry.IsProxyNode() )
			{
				//lets update the root so we later can update all proxies
				PwEntry root = m_database.GetProxyTargetFor(lastModifiedEntry);
				//check if there are real changes! if not we are done here
				if (lastModifiedEntry.IsSimilarTo(root, true))
				{
					return Changes.None;
				}
				PwGroup parent = root.ParentGroup;

				root.CreateBackup( m_database );  //rootNode_X should save all modifications in history
				parent.Entries.Remove( root );

				PwEntry updatedRoot = lastModifiedEntry.CloneDeep();
				updatedRoot.Uuid = root.Uuid;
				updatedRoot.SetParent(parent);
				//special handling for userRootNodes because they have a homefolder
				if(root.IsUserRootNode())
				{
					//maybe the oldUserName has changed to => the homefolder should have the new name also
					//we also want to have the same icons everywhere
					parent.Name = updatedRoot.GetTitle();
					parent.IconId = updatedRoot.IconId;
				}
				else
				{
					updatedRoot.Strings.Remove(KeeShare.UuidLinkField );
				}
				changeFlag |= UpdateProxyInformation(updatedRoot);
				changeFlag |= Changes.GroupDeleted;
			}
			else
			{
				changeFlag |= UpdateProxyInformation( lastModifiedEntry );
			}
			pe_lastModedEntry = GetLastModifiedEntry();
			return changeFlag;
		}
        
		/// <summary>
		/// Propagates possible changes of a rootNode to all of his proxyNodes
		/// </summary>
		/// <param name="root">The rootNode we want to propagate</param>
		/// <returns>True if the function has made changes to the database.</returns>
		private Changes UpdateProxyInformation(PwEntry root)
		{
			Changes changeFlag = Changes.None;
			//get all relevant proxies
			//copy new information from root to proxies
			PwObjectList<PwEntry> allProxies = m_database.GetAllProxyNodes();
			foreach( PwEntry proxy in allProxies )
			{ 
				//check if the proxy matches to the root and has changes! if not we are done here
				if(proxy.IsProxyOf(root) && !proxy.IsSimilarTo(root, true))
				{
					PwGroup parent = proxy.ParentGroup;
					bool success = parent.Entries.Remove( proxy );
					Debug.Assert(success);
					PwEntry duplicate = root.CloneDeep();
					duplicate.Uuid = proxy.Uuid;
					//if the rootNode was a userRoot, the StringFiledUidLink is set automatically in a clone
					//but if not we have to set it manually
					if( !root.IsUserRootNode() )
					{
                        duplicate.MakeToProxyOf(root);
					}
					duplicate.SetParent(parent);
					changeFlag |= Changes.EntryCreated;
				}
			}
			return changeFlag;
		}

		/// <summary>
		/// The funciton finds the last modified entry in the database.
		/// </summary>
		/// <returns>The last modified PwEntry of the database.</returns>
		private PwEntry GetLastModifiedEntry()
		{
			PwObjectList<PwEntry> allEntries = m_database.RootGroup.GetEntries( true );
			PwEntry lastModified = null;
			foreach( PwEntry entry in allEntries )
			{
				if (lastModified == null || entry.LastModificationTime.Ticks > lastModified.LastModificationTime.Ticks)
				{
					lastModified = entry;
				}
			}
			return lastModified;
		}

		/// <summary>
		/// The function ensures, that a RecycleBin folder exists in the copyRootGroup of the actual database
		/// </summary>
		/// <returns>CommonChange = true, if made changes to the database.</returns>
		private Changes EnsureRecycleBin()
		{
			// TODO: Check if KeePass can ensure the bin
			if (! m_database.RecycleBinEnabled ||  m_database.RootGroup.FindGroup(m_database.RecycleBinUuid, true) != null )
			{
				return Changes.None;
			}
			// Code is Copy'n'Paste from KeePass
			PwGroup trash = new PwGroup( true, true, KPRes.RecycleBin, PwIcon.TrashBin );
			trash.EnableAutoType = false;
			trash.EnableSearching = false;
			trash.IsExpanded = !Program.Config.Defaults.RecycleBinCollapse;
			trash.SetParent(m_database.RootGroup);
			m_database.RecycleBinUuid = trash.Uuid;
			return Changes.GroupCreated;
		}
	}
}
