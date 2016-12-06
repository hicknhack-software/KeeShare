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

using System.Diagnostics;
using KeePassLib;
using KeePassLib.Collections;
using KeePassLib.Interfaces;
using KeePassLib.Serialization;
using System.IO;
using System.Linq;
using System;
using System.Collections.Generic;
using KeePassLib.Security;

namespace KeeShare
{
	public static class ExtensionMethods
	{
        public static string ToDebugString(this PwEntry entry)
        {
            return "\"" + entry.Strings.ReadSafe(KeeShare.TitleField) + "\" " + entry.Uuid.ToHexString() + " " + entry.IsProxyNode();
        }

        public static string ToDebugString(this PwGroup group)
        {
            return "\"" + group.Name + "\" " + group.Uuid.ToHexString();
        }

        public static void SetTitle(this PwEntry entry, string title)
        {
            entry.Strings.Set(KeeShare.TitleField, new ProtectedString(false, title));
        }

        public static string GetTitle(this PwEntry entry)
        {
            return entry.Strings.ReadSafe(KeeShare.TitleField);
        }

        public static void SetPassword(this PwEntry entry, string password)
        {
            entry.Strings.Set(KeeShare.PasswordField, new ProtectedString(true, password));
        }

        public static void AddExportSource(this PwEntry entry, string source)
        {
            string sources = entry.Strings.ReadSafe(KeeShare.SynchronizationSourceField);
            if( !sources.Contains(source) )
            { 
                sources += " " + source;
                entry.Strings.Set(KeeShare.SynchronizationSourceField, new ProtectedString(false, sources.Trim()));
            }
        }

        public static bool HasExportSource(this PwEntry entry, string source = null)
        {
            if(source == null)
            {
                return entry.Strings.GetKeys().Contains(KeeShare.SynchronizationSourceField);
            }
            return entry.Strings.ReadSafe(KeeShare.SynchronizationSourceField).Contains(source);
        }

        public static void MakeToProxyOf(this PwEntry entry, PwEntry target)
        {
            entry.Strings.Set(KeeShare.UuidLinkField, new ProtectedString(true, target.Uuid.ToHexString()));
        }

        public static bool IsProxyOf(this PwEntry proxy, PwEntry target)
        {
            return proxy.ProxyTargetIdentifier() == target.Uuid.ToHexString();
        }

        public static string ProxyTargetIdentifier(this PwEntry entry)
        {
            return entry.Strings.ReadSafe(KeeShare.UuidLinkField);
        }

        /// <summary>
		/// The function compares two PwEntries in every scope except the Uuid
		/// </summary>
		/// <param name="entry1">the first entry</param>
		/// <param name="entry2">the second entry</param>
		/// <param name="bIgnoreKeeShareFields">Should the KeeShare-specific fields be ignored?</param>
		/// <returns>True if both entries are equal in all field, accordingly to the parametersettings</returns>
		public static bool IsSimilarTo(this PwEntry entry1, PwEntry entry2, bool bIgnoreKeeShareFields)
        {
            //if both are null they are equal
            if (entry1 == null && entry2 == null)
            {
                return true;
            }
            //if only one of them is null we could not clone it => they are not equal
            if (entry1 == null || entry2 == null)
            {
                return false;
            }

            PwEntry copy1 = entry1.CloneDeep();
            PwEntry copy2 = entry2.CloneDeep();
            if (bIgnoreKeeShareFields)
            {
                copy1.Strings.Remove(KeeShare.UuidLinkField);
                copy2.Strings.Remove(KeeShare.UuidLinkField);
            }

            //we have to make the Uuids and creation times equal, because PwEntry.EqualsEntry compares these too
            //and returns false if they are not equal!!
            copy1.SetUuid(copy2.Uuid, false);
            copy1.CreationTime = copy2.CreationTime;

            PwCompareOptions opts = PwCompareOptions.IgnoreHistory
                | PwCompareOptions.IgnoreLastAccess
                | PwCompareOptions.IgnoreLastBackup
                | PwCompareOptions.IgnoreLastMod
                | PwCompareOptions.IgnoreParentGroup
                | PwCompareOptions.IgnoreTimes;
            return copy1.EqualsEntry(copy2, opts, MemProtCmpMode.Full);
        }

        /// <summary>
        /// Checks if the given item is directly or indirectly contained in the given parent
        /// </summary>
        /// <param name="item"></param>
        /// <param name="origParent"></param>
        /// <returns></returns>
        public static bool IsInsideParent(this IStructureItem item, IStructureItem parent)
		{
			Debug.Assert( null != item );
			Debug.Assert( null != parent );

			if( item.ParentGroup == null )
			{
				return false;
			}
			return item.ParentGroup == parent
				|| IsInsideParent( item.ParentGroup, parent );
		}

        /// <summary>
        /// Looks for the root group of the given item
        /// </summary>
        /// <param name="item"></param>
        /// <returns></returns>
        public static PwGroup GetRootGroup(this IStructureItem item)
        {
            PwGroup group = item is PwGroup ? item as PwGroup : item.ParentGroup;
            while( group.ParentGroup != null )
            {
                group = group.ParentGroup;
            }
            return group;
        }

		/// <summary>
		/// The function checks if the specified folder was a HomeFolder. That means if it
		/// has a rootNode_X with the same "Title" as its Name in his entries.
		/// </summary>
		/// <param name="group">The group to be checked</param>
		/// <returns>True if the group was a homefolder.</returns>
		public static bool IsHome(this PwGroup group)
		{
			Debug.Assert( null != group );
			return group.Entries
				.Any(entry => entry.IsUserRootNode() && group.Notes.Contains(entry.Uuid.ToHexString()) );
		}

		/// <summary>
		/// Checks if the specified node is a valid KeeShare rootNode which represents a user.
		/// </summary>
		/// <param name="entry"></param>
		/// <returns>True is the entry is a valid UserRootNode.</returns>
		public static bool IsUserRootNode(this PwEntry entry)
		{
			Debug.Assert( null != entry );
			return entry.Strings.ReadSafe(KeeShare.UuidLinkField ) == entry.Uuid.ToHexString();
		}

		public static bool IsUserNode(this PwEntry entry)
		{
			Debug.Assert(null != entry);
			return entry.Strings.Exists(KeeShare.UuidLinkField);
		}

		/// <summary>
		/// The function checks if a pwentry is a normal pwentry. That means
		/// it is no spcial KeeShareEntry
		/// </summary>
		/// <param name="entry"></param>
		/// <returns>True if the PwEntry is no special OwdShareEntry</returns>
		public static bool IsNormalPwEntry(this PwEntry entry)
		{
			Debug.Assert( null != entry );

			return !entry.Strings.Exists(KeeShare.UuidLinkField)
				&& !entry.Strings.Exists(KeeShare.SourcePathField);
				
		}

		/// <summary>
		/// The function checks if a given PwEntry is a valid KeeShareProxyNode.
		/// </summary>
		/// <param name="entry"></param>
		/// <returns>True if the pwentry is a proxyNode</returns>
		public static bool IsProxyNode(this PwEntry entry)
		{
			Debug.Assert( null != entry );
			if( ! entry.Strings.Exists(KeeShare.UuidLinkField ) )
			{
				return false;
			}
			return entry.Strings.ReadSafe(KeeShare.UuidLinkField) != entry.Uuid.ToHexString();
		}

		public static bool IsValidSource(this PwEntry entry)
		{
			if( entry != null && entry.Strings.Exists(KeeShare.SourcePathField ) )
			{
				string path = entry.Strings.ReadSafe(KeeShare.SourcePathField );
				if( IOConnectionInfo.FromPath( path ).CanProbablyAccess() )
				{
					return true;
				}
			}
			return false;
		}

		public static bool IsValidExportInfo(this PwGroup group)
		{
			return group != null
				&& Directory.Exists( group.Name );
		}

		public static PwGroup FindCreateGroup(this PwDatabase database, string tag, string name, PwIcon icon = PwIcon.Folder)
		{
			foreach (PwGroup rootGroup in database.RootGroup.GetGroups(true))
			{
				if (rootGroup.Notes.Contains(tag))
				{
					return rootGroup;
				}
			}
			//if we cant find the group yet, we create a new one and add it to the rootGroup
			PwGroup group = new PwGroup(true, true, name, icon);
			group.Notes = tag;
			group.SetParent(database.RootGroup);
			Debug.Assert(null != group, "group for " + tag + " - " + name + " is 'null' but should not!");
			return group;
		}

        public static PwGroup FindCreateGroup(this PwDatabase database, string tag, string name, PwGroup parent, PwIcon icon = PwIcon.Folder)
        {
            PwGroup group = database.FindCreateGroup(tag, name, icon);
            if( group.ParentGroup != parent)
            {
                group.MoveToParent(parent);
            }
            return group;
        }

        public static bool IsRegistered(this PwDatabase database, string id, string tag)
        {
            //Debug.Assert(database.IsOpen);
            return database.CustomData.Exists(id)
                && database.CustomData.Get(id) == tag;
        }

        public static bool Register(this PwDatabase database, string id, string tag)
        {
            //Debug.Assert(database.IsOpen);
            database.CustomData.Set(id, tag);
            return true;
        }

        public static bool Unregister(this PwDatabase database, string id)
        {
            //Debug.Assert(database.IsOpen);
            database.CustomData.Remove(id);
            return true;
        }

        public static PwDatabase CloneDeep(this PwDatabase database, PwGroup rootGroup = null)
        {
            PwDatabase clone = new PwDatabase();
            var cloneRootGroup = database.RootGroup.CloneDeep();
            var cloneGroups = new List<PwGroup>() { cloneRootGroup };
            // Workaround - DeepClone does not adjust the parents accordingly
            while (cloneGroups.Count > 0)
            {
                var currentGroup = cloneGroups.First();
                cloneGroups.Remove(currentGroup);
                foreach (var cloneGroup in currentGroup.Groups.ToList())
                {
                    currentGroup.Groups.Remove(cloneGroup);
                    cloneGroup.SetParent(currentGroup, true);
                }
                foreach (var cloneEntry in currentGroup.Entries.ToList())
                {
                    currentGroup.Entries.Remove(cloneEntry);
                    cloneEntry.SetParent(currentGroup, true);
                }
                cloneGroups.AddRange(currentGroup.Groups);
            }
            if( rootGroup == null )
            {
                clone.RootGroup = cloneRootGroup;
            }
            else
            {
                // We simulate the same origin to remove the need of KeePass to import the root node
                var changedRootGroup = rootGroup.CloneDeep();
                changedRootGroup.Entries.Clear();
                changedRootGroup.Groups.Clear();
                foreach(var entry in cloneRootGroup.Entries.ToList())
                {
                    cloneRootGroup.Entries.Remove(entry);
                    entry.SetParent(changedRootGroup);
                }
                foreach (var group in cloneRootGroup.Groups.ToList())
                {
                    cloneRootGroup.Groups.Remove(group);
                    group.SetParent(changedRootGroup);
                }
                clone.RootGroup = changedRootGroup;
            }
            return clone;
        }


        public static void DeleteFrom(this PwEntry entry, PwGroup parent, PwDatabase database = null)
        {
            if (database != null)
            {
                // create the delete marker
                PwDeletedObject deleteMarker = new PwDeletedObject(entry.Uuid, DateTime.Now);
                database.DeletedObjects.Add(deleteMarker);
            }
            // TODO CK: Potential memory leak? are there dangling references?
            var success = parent.Entries.Remove(entry);
            Debug.Assert(success);
        }

        public static void DeleteFrom(this PwGroup group, PwGroup parent, PwDatabase database)
        {
            //first remove all entries in the group
            group.DeleteAllObjects(database);
            // create the delete marker
            PwDeletedObject deleteMarker = new PwDeletedObject(group.Uuid, DateTime.Now);
            database.DeletedObjects.Add(deleteMarker);
            //now we can remove the empty group
            parent.Groups.Remove(group);
        }

        public static void SetParent(this PwEntry entry, PwGroup parent, bool bTakeOwnership = true)
        {
            parent.AddEntry(entry, bTakeOwnership);
        }

        public static void SetParent(this PwGroup group, PwGroup parent, bool bTakeOwnership = true)
        {
            parent.AddGroup(group, bTakeOwnership);
        }


        public static void MoveToParent(this PwGroup group, PwGroup parent)
        {
            group.ParentGroup.Groups.Remove(group);
            group.SetParent(parent);
        }

        public static PwGroup GetSyncGroup(this PwDatabase database)
        {
            return database.FindCreateGroup(KeeShare.SyncGroupTag, KeeShare.SyncGroupName, PwIcon.WorldSocket);
        }

        public static PwGroup GetExportGroup(this PwDatabase database)
        {
            return database.FindCreateGroup(KeeShare.ExportGroupTag, KeeShare.ExportGroupName, GetSyncGroup(database), PwIcon.WorldSocket);
        }

        public static PwGroup GetImportGroup(this PwDatabase database)
        {
            Debug.Assert(database != null);
            return database.FindCreateGroup(KeeShare.ImportGroupTag, KeeShare.ImportGroupName, GetSyncGroup(database), PwIcon.WorldSocket);
        }

        //using these properties ensures that the groups are existent everytime we try to get them
        /// <summary>
        /// References the group where KeeShare will store all user entries.
        /// From here you can get an overview and organize your users.
        /// It also empowers you to share passwords with single users, by dragNdrop them
        /// unto the users home folder.
        /// </summary>
        public static PwGroup GetUsersGroup(this PwDatabase database)
        {
            Debug.Assert(database != null);
            return database.FindCreateGroup(KeeShare.UsersGroupTag, KeeShare.UsersGroupName, PwIcon.Home);
        }

        /// <summary>
        /// references the group whre you can organize your user entries in groups
        /// so it will be easier to share passwords through a whole group of users
        /// </summary>
        public static PwGroup GetGroupsGroup(this PwDatabase database)
        {
            Debug.Assert(database != null);
            return database.FindCreateGroup(KeeShare.GroupsGroupTag, KeeShare.GroupsGroupName, PwIcon.MultiKeys);
        }

        /// <summary>
        /// The <c>GetUsersHome</c> function looks for the home folder of a user.
        /// If it doesn't exist, a new one will be created.
        /// The createIfNotFound parameter is optional.
        /// </summary>
        /// <param name="userRoot">UserRootNode which we want to find the home folder of.</param>
        /// <param name="createIfNotFound">If not set the default value is true. That
        /// means that a home will be created if not found!</param>
        /// <returns>PwGroup homefolder of a user</returns>
        public static PwGroup GetUserHomeFor(this PwDatabase database, PwEntry userRoot, bool createIfNotFound = true)
        {
            Debug.Assert(database != null);
            PwGroup usersGroup = GetUsersGroup(database);
            PwObjectList<PwGroup> usersHomes = usersGroup.GetGroups(false);
            foreach (PwGroup pg in usersHomes)
            {
                if (pg.Notes.Contains(userRoot.Uuid.ToHexString()))
                {
                    return pg;
                }
            }
            //if home was not found then create it
            if (createIfNotFound)
            {
                string name = userRoot.Strings.ReadSafe("Title");
                PwGroup newUserGroup = new PwGroup(true, true, name, PwIcon.UserKey);
                newUserGroup.Notes += userRoot.Uuid.ToHexString();
                newUserGroup.SetParent(usersGroup);
                return newUserGroup;
            }
            return null;
        }

        /// <summary>
		/// The function finds the rootNode to your entry
		/// </summary>
		/// <param name="proxy">the entry we want to find the rootNode of</param>
		/// <returns>Null if no root was found! The rootNode otherwise.</returns>
        public static PwEntry GetProxyTargetFor(this PwDatabase database, PwEntry proxy)
        {
            Debug.Assert(database != null);
            PwObjectList<PwEntry> allEntries = database.RootGroup.GetEntries(true);
            foreach (PwEntry entry in allEntries)
            {
                if (entry.Uuid.ToHexString() == proxy.Strings.ReadSafe(KeeShare.UuidLinkField))
                {
                    return entry;
                }
            }
            Debug.Fail("No root entry found");
            return null;
        }
        /// <summary>
        /// Finds all UserRootNodes, which means the returned list contains all users.
        /// </summary>
        /// <returns>A list which contains all UserRootNodes of the actual database.</returns>
        public static PwObjectList<PwEntry> GetAllUserNodes(this PwDatabase database)
        {
            PwObjectList<PwEntry> allEntries = database.RootGroup.GetEntries(true);
            PwObjectList<PwEntry> rootList = new PwObjectList<PwEntry>();
            foreach (PwEntry pe in allEntries)
            {
                if (pe.IsUserRootNode())
                {
                    rootList.Add(pe);
                }
            }
            return rootList;
        }

        public static PwObjectList<PwEntry> GetAllProxyTargets(this PwDatabase database)
        {
            PwObjectList<PwEntry> allEntries = database.RootGroup.GetEntries(true);
            PwObjectList<PwEntry> rootList = new PwObjectList<PwEntry>();
            foreach (PwEntry pe in allEntries)
            {
                if (pe.IsUserRootNode() || pe.IsNormalPwEntry())
                {
                    rootList.Add(pe);
                }
            }
            return rootList;
        }

        /// <summary>
		/// Finds all Proxynodes in the database. That means all PwEntries with a 
		/// StringFieldUidLink which points to another PwEntry
		/// </summary>
		/// <returns>A <c>PwObjectList<PwEntry></c> which contains all proxy nodes of the actual DB.</returns>
		public static PwObjectList<PwEntry> GetAllProxyNodes(this PwDatabase database)
        {
            PwObjectList<PwEntry> allEntries = database.RootGroup.GetEntries(true);
            PwObjectList<PwEntry> proxyList = new PwObjectList<PwEntry>();
            foreach (PwEntry entry in allEntries)
            {
                if (entry.IsProxyNode())
                {
                    proxyList.Add(entry);
                }
            }
            return proxyList;
        }

        /// <summary>
		/// Checks if the given entry is a proxy of a UserRootNode
		/// </summary>
		/// <param name="entry">the entry you want to check</param>
		/// <returns>True if the entry is a UserProxy</returns>
		public static bool IsUserProxy(this PwDatabase database, PwEntry entry)
        {
            if (!entry.IsProxyNode())
            {
                return false;
            }
            Debug.Assert(database != null);
            foreach (PwEntry root in ExtensionMethods.GetAllUserNodes(database))
            {
                if (root.Uuid.ToHexString() == entry.Strings.ReadSafe(KeeShare.UuidLinkField))
                {
                    return true;
                }
            }
            return false;
        }

        public static bool IsPasswordProxy(this PwDatabase database, PwEntry entry)
        {
            return entry.IsProxyNode() && !database.IsUserProxy(entry);
        }

        public static PwEntry DuplicateTo(this PwEntry entry, PwGroup parent)
        {
            PwEntry copy = entry.CloneDeep();
            //we dont want to share our history
            copy.History.Clear();
            //HACK: CloneDeep introduces the copy into the parent node, therefore SetParent triggers a change of the parent
            //      which shouldn't be - the extended ProtectionSection in KeeShare should prevent interference, but a 
            //      a clean way to clone a node without cloning children and without hooking it into a tree would be nice
            copy.SetParent(parent);
            return copy;
        }

        public static PwGroup DuplicateTo(this PwGroup group, PwGroup parent)
        {
            PwGroup copy = group.CloneStructure();
            copy.Groups.Clear();
            copy.Entries.Clear();
            //HACK: CloneDeep introduces the copy into the parent node, therefore SetParent triggers a change of the parent
            //      which shouldn't be - the extended ProtectionSection in KeeShare should prevent interference, but a 
            //      a clean way to clone a node without cloning children and without hooking it into a tree would be nice
            copy.SetParent(parent);
            return copy;
        }

        public static PwEntry DuplicateEntryTo(this PwDatabase originalDB, PwEntry originalEntry, PwDatabase copyDB)
        {
            PwGroup copyParent = originalDB.DuplicateGroupTo(originalEntry.ParentGroup, copyDB);
            PwEntry copyEntry = originalEntry.DuplicateTo(copyParent);
            return copyEntry;
        }

        /// <summary>
		/// The function finds a specified group (by Uuid) in the copyDb.
		/// The function creates the group if it was not present in the 
		/// copyDB yet and ensures the correct path.
		/// </summary>
        /// <param name="originalDB">Ausgangsdatenbank</param>
		/// <param name="originalGroup">The parent PwGroup in the original Database.</param>
		/// <param name="copyDB">The Database where we want to copy the group to.</param>
		/// <returns>The Group in the copy of the database that represents the origGrp in 
		/// the original database.</returns>
        public static PwGroup DuplicateGroupTo(this PwDatabase originalDB, PwGroup originalGroup, PwDatabase copyDB)
        {
            if (originalGroup == originalDB.RootGroup)
            {
                return copyDB.RootGroup;
            }
            PwGroup copyGroup = copyDB.RootGroup.FindGroup(originalGroup.Uuid, true);
            if (copyGroup != null)
            {
                return copyGroup;
            }
            PwGroup copyParent = originalDB.DuplicateGroupTo(originalGroup.ParentGroup, copyDB);
            copyGroup = originalGroup.DuplicateTo(copyParent);
            return copyGroup;
        }
    }
}
