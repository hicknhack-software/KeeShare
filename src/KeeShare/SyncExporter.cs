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
using KeePassLib.Collections;
using KeePassLib.Cryptography.Cipher;
using KeePassLib.Serialization;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;

namespace KeeShare {
  public class SyncExporter {
    public const string FileExtension = ".kdbx";
    /// <summary>
    /// The function checks if there are any changes and if so, it automatically starts
    /// to export everything new.
    /// </summary>
    public void Export(PwDatabase database) {
      PwObjectList<PwEntry> allUsers = database.GetAllUserNodes();
      foreach (PwEntry root in allUsers) {
        // Currently there is no way to check, if nodes were added which have a time older than the last export time
        // using the import tool or our own synchronization - it would be possible to open the last export and only 
        // update the differences, but this would be prone to errorsdue to the complexity - therefore we use the 
        // pessimistic way and export everything at once and let KeePass-MergeIn handle the load
        //long lastExport;
        //if( Int64.TryParse(root.Strings.ReadSafe(KeeShare.StringFieldLastExport), out lastExport))
        //{
        //    //we check every shared item for a change after the lastExport
        //    PwObjectList<PwGroup> sharedFolders = GetSharedFolders(database, root);
        //    foreach (PwGroup group in sharedFolders)
        //    {
        //        bool done = false;
        //        foreach (PwEntry entry in group.Entries)
        //        {
        //            //if we find some entry that was changed after the last export, then we create a new delta-container
        //            //and export it. after that we can stop the search and continue with the next user.
        //            if (lastExport < entry.LastModificationTime.Ticks
        //                || lastExport < entry.CreationTime.Ticks)
        //            {
        //                Console.WriteLine("EXPORT TIMED FOR" + root.Strings.ReadSafe(KeeShare.TitleField));
        //                Export(database, root);
        //                done = true;
        //                break;
        //            }
        //            Console.WriteLine("NO EXPORT TIMED FOR" + root.GetTitle() + " " + lastExport + " " + entry.GetTitle() + " " + entry.LastModificationTime.Ticks);
        //        }
        //        if (done == true)
        //        {
        //            break;
        //        }
        //    }
        //}
        //else 
        //{
        //if we could not get the lastExportDate we go for sure and export everything for that user!
        Export(database, root);
        //}
      }
    }


    /// <summary>
    /// a fuction which returns a list of all folder which are shared to a specified user
    /// </summary>
    /// <param name="userRoot">The rootNode of the user you want to export you data to.</param>
    /// <returns>A <c>PwObjectList<PwGroup></c> which contains all PwGroups which are shared to
    /// the given user.</returns>
    public PwObjectList<PwGroup> GetSharedFolders(PwDatabase database, PwEntry userRoot) {
      PwObjectList<PwGroup> sharedFolders = new PwObjectList<PwGroup>();
      foreach (PwEntry proxy in database.GetAllProxyNodes()) {
        if (userRoot.Uuid.ToHexString() == proxy.Strings.ReadSafe(KeeShare.UuidLinkField)) {
          PwGroup group = proxy.ParentGroup;
          //we don't want to share the "Users"-folder, so if we find it, we skip it!
          if (group == database.GetUsersGroup()) {
            continue;
          }
          sharedFolders.Add(group);
          //include all subfolders
          sharedFolders.Add(group.GetGroups(true));
        }
      }
      //find the homeFolder and add it to the sharedList
      sharedFolders.Add(database.GetUserHomeFor(userRoot));
      return sharedFolders;
    }

    /// <summary>
    /// The function collects all export pathes for the given user. All these
    /// pathes are used to get a copy of the delta container
    /// </summary>
    /// <param name="rootNode">Specifies the user we want to know the expPathes of.</param>
    /// <returns>A <c>List<string></c> containing all the expPathes.</returns>
    private List<string> GetAllExportPaths(PwDatabase database, PwEntry rootNode) {
      List<string> expList = new List<string>();
      PwGroup exportGroup = database.GetExportGroup();
      foreach (PwEntry proxy in exportGroup.GetEntries(true)) {
        if (proxy.Strings.ReadSafe(KeeShare.UuidLinkField) == rootNode.Uuid.ToHexString()) {
          if (proxy.ParentGroup.IsValidExportInfo()) {
            expList.Add(proxy.ParentGroup.Name);
          }
        }
      }
      return expList;
    }

    /// <summary>
    /// The functions tests if a group is a special group which was created for 
    /// PwdSahre only.
    /// </summary>
    /// <param name="group">The group we want to test.</param>
    /// <returns>True if the specified group was a special KeeShare group.</returns>
    private bool IsKeeShareFolder(PwDatabase database, PwGroup group) {
      Debug.Assert(group != null);

      //only three groups are interesting for us: "Users" / "Groups" / "SyncGroup"
      return group.ParentGroup != null
          && (group.IsInsideParent(database.GetUsersGroup())
              || group.IsInsideParent(database.GetGroupsGroup())
              || group.IsInsideParent(database.GetSyncGroup()));
    }



    class EntryTypeComparer : IComparer<PwEntry> {
      public int Compare(PwEntry x, PwEntry y) {
        if (!x.IsNormalPwEntry()) {
          return -1;
        }
        if (!y.IsNormalPwEntry()) {
          return 1;
        }
        return 0;
      }
    }

    /// <summary>
    /// This function creates the correct structured database which will be used
    /// to create the delta container.
    /// </summary>
    /// <param name="sharedFolders">All PwGroups that should be placed in the delta
    /// container. Usually that are the PwGroups that are shared with the specified user.</param>
    /// <returns>A PwDatabae that conatins the hierarchically correct structured database
    /// which could be used to create a delta container.</returns>
    public PwDatabase CreateDeltaDb(PwDatabase database, PwObjectList<PwGroup> sharedFolders) {
      PwDatabase deltaDB = new PwDatabase();
      deltaDB.RootGroup = new PwGroup(true, true) {
        //Uuid = database.RootGroup.Uuid // We set the root group to the same Uuid to identify the source database (does not work for cycles with more hops)
      };

      foreach (PwGroup group in sharedFolders) {
        foreach (PwEntry entry in group.Entries) {
          PwEntry copyEntry = null;
          //do we handle a normal pwentry
          if (entry.IsNormalPwEntry()) {
            //we dont want to share a PwEntry more than once!
            if (null != deltaDB.RootGroup.FindEntry(entry.Uuid, true)) {
              continue;
            }
            // check if our origParent was a normal folder or some KeeShare specific Folder ("Users" / "Groups" / "SyncGroup")
            if (IsKeeShareFolder(database, group)) {
              entry.SetParent(deltaDB.RootGroup);
              copyEntry = entry;
            }
            else  //the entry was located in a normal PwGroup
            {
              copyEntry = database.DuplicateEntryTo(entry, deltaDB);
            }
          }
          //or a pwproxy
          if (database.IsPasswordProxy(entry)) {
            //we only add the rootNode to the copy, because all proxies are only information for KeeShare
            PwEntry entryRoot = database.GetProxyTargetFor(entry);
            //we dont want to share a PwEntry more than once!
            if (null != deltaDB.RootGroup.FindEntry(entryRoot.Uuid, true)) {
              continue;
            }
            copyEntry = database.DuplicateEntryTo(entryRoot, deltaDB);
          }
          if (copyEntry != null) {
            copyEntry.AddExportSource(database.RootGroup.Uuid.ToHexString());
          }
          //everything else (UserProxy and UserRootNodes) we have to ignore!
          //Debug.Assert(!copyDB.HasDuplicateUuids());
        }
      }
      return deltaDB;
    }


    /// <summary>
    /// The function creates exportfiles for the specified user.
    /// </summary>
    /// <param name="userRoot">Specifies the user we want to export to.</param>
    private void Export(PwDatabase database, PwEntry userRoot) {
      var exportPaths = GetAllExportPaths(database, userRoot);
      if (exportPaths.Count == 0) {
        return;
      }
      var sharedFolders = GetSharedFolders(database, userRoot);
      var deltaDB = CreateDeltaDb(database, sharedFolders);
      ExportDatabaseTo(deltaDB, userRoot, exportPaths);
      //save the lastExport time - not needed to set, because we export everything
      //userRoot.Strings.Set(KeeShare.LastExportField, new ProtectedString(false, DateTime.Now.Ticks.ToString()));
    }

    private void ExportDatabaseTo(PwDatabase deltaDB, PwEntry userRoot, List<string> paths) {
      //Save the database encrypted with the KEY specified in the PasswordFiled of the user
      deltaDB.MasterKey = SyncSource.CreateKeyFor(userRoot);
      deltaDB.DataCipherUuid = StandardAesEngine.AesUuid;
      deltaDB.Compression = PwCompressionAlgorithm.GZip;
      deltaDB.MemoryProtection.ProtectPassword = true;
      deltaDB.SetCustomAttribute(KeeShare.AttributeFlags.IsDeltaDatabase, true);

      string fileName = SyncSource.FileNameFor(userRoot);

      foreach (string path in paths) {
        string databasePath = path;
        if (!path.EndsWith(Path.DirectorySeparatorChar.ToString())) {
          databasePath += Path.DirectorySeparatorChar;
        }
        databasePath += fileName + FileExtension;
        deltaDB.SaveAs(IOConnectionInfo.FromPath(databasePath), false, null);
      }
    }

    /// <summary>
    /// This function starts the exportprogress on a selected PwGroup.
    /// That way we can trigger an export for some users manually.
    /// </summary>
    /// <param name="selectedGroup">Specifies the PwGroup whoch contains all "users" 
    /// (userProxies) we want to create a export.</param>
    private void Export(PwDatabase database, PwGroup selectedGroup) {
      ExportUsersFolder(database, selectedGroup);
      ExportUserHome(database, selectedGroup);
      ExportUsingGroupsOfUser(database, selectedGroup);
    }

    private void ExportUsingGroupsOfUser(PwDatabase database, PwGroup selectedGroup) {
      //if the menu was called from a GroupsGroup we try to find all users in that group and then export
      //the pwds for all of them.
      PwGroup groupsGroup = database.GetGroupsGroup();
      if (selectedGroup == groupsGroup || selectedGroup.IsInsideParent(groupsGroup)) {
        foreach (PwEntry entry in selectedGroup.GetEntries(true)) {
          if (database.IsUserProxy(entry)) {
            Export(database, database.GetProxyTargetFor(entry));
          }
        }
      }
    }

    private void ExportUserHome(PwDatabase database, PwGroup selectedGroup) {
      //if the seleced group was a user-home, we only export the pwds for that user
      if (selectedGroup.IsHome()) {
        foreach (PwEntry entry in selectedGroup.GetEntries(false)) {
          if (entry.IsUserRootNode() && selectedGroup.Notes.Contains(entry.Uuid.ToHexString())) {
            Export(database, entry);
            break;
          }
        }
      }
    }

    private void ExportUsersFolder(PwDatabase database, PwGroup selectedGroup) {
      //if we try to export for the whole "Users"-folder, we export
      //the passwords for all users here.
      if (selectedGroup == database.GetUsersGroup()) {
        PwObjectList<PwEntry> allRoots = database.GetAllUserNodes();
        foreach (PwEntry rootNode in allRoots) {
          Export(database, rootNode);
        }
      }
    }
  }
}
