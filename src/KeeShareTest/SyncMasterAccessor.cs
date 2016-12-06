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
using KeeShare;

namespace KeeShareTest
{
    public class SyncMasterAccessor : SyncMaster
    {
        public PwObjectList<PwGroup> GetSharedFolders(PwEntry userRoot)
        {
            return m_exporter.GetSharedFolders(m_database, userRoot);
        }

        public PwDatabase CreateDeltaDb(PwObjectList<PwGroup> sharedFolders)
        {
            return m_exporter.CreateDeltaDb(m_database, sharedFolders);
        }
    }

    public class SyncImporterAccessor : SyncImporter
    {
        public void MergeInAccessor(PwDatabase target, PwDatabase source)
        {
            TestHelper.DelayAction();
            MergeIn(target, source);
        }
    }
}
