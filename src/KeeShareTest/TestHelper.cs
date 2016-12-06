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
using System.Linq;
using System.IO;

namespace KeeShareTest
{
    public class TestHelper : KeeShare.KeeShare
    {
        public static PwDatabase CreateDatabase(string recyclerName = "")
        {
            var database = new PwDatabase();
            database.RootGroup = new PwGroup(true, true);
            database.RootGroup.Name = "RootGroup";
            if( recyclerName != "")
            {
                var trash = new PwGroup(true, true, recyclerName, PwIcon.TrashBin);
                database.RootGroup.AddGroup(trash, true);
                database.RecycleBinUuid = trash.Uuid;
            }
            return database;
        }


        public static PwGroup GetGroupByTagFor(PwDatabase database, string tag, bool recursive = false)
        {
            foreach (PwGroup rootGroup in database.RootGroup.GetGroups(recursive))
            {
                if (rootGroup.Notes.Contains(tag))
                {
                    return rootGroup;
                }
            }
            return null;
        }

        public static PwGroup GetUsersGroupFor(PwDatabase database)
        {
            return GetGroupByTagFor(database, KeeShare.KeeShare.UsersGroupTag);
        }

        public static PwGroup GetGroupsGroupFor(PwDatabase database)
        {
            return GetGroupByTagFor(database, KeeShare.KeeShare.GroupsGroupTag);
        }


        public static PwEntry GetUserRootNodeFor(PwDatabase database, uint iUser)
        {
            return GetUsersGroupFor(database).Groups.GetAt(iUser).Entries.GetAt(0);
        }

        public static PwEntry GetUserRootProxyFor(PwDatabase database, uint iUser)
        {
            return GetUsersGroupFor(database).Entries.GetAt(iUser);
        }

        public static PwGroup GetUserHomeNodeFor(PwDatabase database, uint iUser)
        {
            return GetUsersGroupFor(database).Groups.GetAt(iUser);
        }

        public static PwGroup GetUserHomeNodeByNameFor(PwDatabase database, string name)
        {
            foreach (PwGroup group in GetUsersGroupFor(database).Groups)
            {
                if (group.Name == name)
                {
                    return group;
                }
            }
            return null;
        }

        public static PwGroup GetExportGroup(PwDatabase database)
        {
            var syncGroup = database.RootGroup.Groups.Single(g => g.Notes.Contains(KeeShare.KeeShare.SyncGroupTag));
            if( syncGroup != null)
            {
                return syncGroup.Groups.Single(g => g.Notes.Contains(KeeShare.KeeShare.ExportGroupTag));
            }
            return null;
            
        }

        public static PwEntry GetUserRootNodeByNameFor(PwDatabase database, string name)
        {
            var group = GetUserHomeNodeByNameFor(database, name);
            if( group == null )
            {
                return null;
            }
            return group.Entries.GetAt(0);
        }

        public static PwGroup GetGroupByUuidFor(PwDatabase database, PwUuid uuid)
        {
            return database.RootGroup.FindGroup(uuid, true);
        }

        public static void DelayAction()
        {
            System.Threading.Thread.Sleep(10);
        }

        public static void SimulateTouch(PwEntry entry)
        {
            DelayAction();
            entry.Touch(true, false);
            //entry.LastModificationTime = entry.LastModificationTime.AddMilliseconds(23);
        }

        public static void SimulateTouch(PwGroup group)
        {
            DelayAction();
            group.Touch(true, false);
            //group.LastModificationTime = entrygroup.LastModificationTime.AddMilliseconds(23);
        }

        public static void CleanFilesystem(string path)
        {
            if (Directory.Exists(path))
            {
                Directory.Delete(path, true);
                DelayAction(); // Give the system some time to clean up
            }
            Directory.CreateDirectory(path);
        }
    }
}
