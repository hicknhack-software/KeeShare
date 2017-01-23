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
using KeePassLib.Keys;
using KeePassLib.Serialization;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Drawing;
using System.Linq;

namespace KeeShare {
  public delegate void UpdatedEventHandler(object sender, PwGroup group);

  public class SyncImporter {
    public event UpdatedEventHandler Imported;

    /// <summary>
    /// The function tries to merge possible updates from the deltaDB into
    /// the actual database. If there was made changes to the actualDB, then
    /// the function fires a event, which cause the KeePass UI to update and
    /// show the "save"-button.
    /// </summary>
    public void Import(object sender, SyncSource source) {
      Debug.Assert(source.DestinationDB != null && source.DestinationDB.RootGroup != null);
      //merge all updates in
      PwDatabase deltaDB = new PwDatabase();
      try {
        deltaDB.Open(IOConnectionInfo.FromPath(source.Location), source.Key, null);
      }
      catch (InvalidCompositeKeyException e) {
        Debug.WriteLine("Wrong key! exception was: " + e.Message);
        //brand this entry as a false one => red bg-color and "X" as group icon
        ShowErrorHighlight(source.DestinationDB, source.Uuid);
        if (Imported != null) Imported.Invoke(this, source.DestinationDB.RootGroup);
        return;
      }
      catch (Exception e) {
        Debug.WriteLine("Standard exception was thrown during deltaDB.Open(): " + e.Message);
        //maybe the process has not finished writing to our file, but the filewtcher fires our event
        //sourceEntryUuid we have to ignore it and wait for the next one.
        return;
      }
      HideErrorHighlight(source.DestinationDB, source.Uuid);
      MergeIn(source.DestinationDB, deltaDB);
      deltaDB.Close();
    }

    private void ShowErrorHighlight(PwDatabase target, PwUuid uuid) {
      var entry = target.RootGroup.FindEntry(uuid, true);
      entry.BackgroundColor = Color.Red;
      entry.ParentGroup.IconId = PwIcon.Expired;
    }

    private void HideErrorHighlight(PwDatabase target, PwUuid uuid) {
      var entry = target.RootGroup.FindEntry(uuid, true);
      entry.BackgroundColor = Color.Empty;
      entry.ParentGroup.IconId = PwIcon.NetworkServer;
    }

    protected void MergeIn(PwDatabase target, PwDatabase source) {
      //remember stats of destDB to guess if we merged in something
      //maybe we only look for the lastChanged entry
      var clone = source.CloneDeep(target.RootGroup);
      clone.SetCustomAttribute(KeeShare.AttributeFlags.IsTemporaryDatabase, true);
      var cyclicEntries = new List<PwEntry>();
      foreach (var cloneEntry in clone.RootGroup.GetEntries(true).ToList()) {
        if (cloneEntry.HasExportSource(target.RootGroup.Uuid.ToHexString())) {
          cloneEntry.DeleteFrom(cloneEntry.ParentGroup);
          cyclicEntries.Add(cloneEntry);
        }
      }

      Console.WriteLine("Prevent import of nodes which are exported from here: " + String.Join(",", cyclicEntries.Select(e => e.GetTitle()).ToArray()));

      DateTime lastChange = DateTime.MinValue;
      foreach (var entry in target.RootGroup.GetEntries(true)) {
        if (entry.LastModificationTime.Ticks > lastChange.Ticks) {
          lastChange = entry.LastModificationTime;
        }
      }
      target.MergeIn(clone, PwMergeMethod.Synchronize);
      foreach (var entry in source.RootGroup.GetEntries(true)) {
        if (entry.LastModificationTime.Ticks > lastChange.Ticks) {
          //set the modified flag of the database true, so the uiUpdate knows which tab should be marked as changed
          target.Modified = true;
        }
      }
      if (Imported != null) Imported.Invoke(this, target.RootGroup);
    }
  }
}
