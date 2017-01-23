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
using System.Diagnostics;
using System.Collections.Generic;
using KeePassLib.Security;
using System.IO;

namespace KeeShare {
  public class SyncMaster {
    protected SyncImporter m_importer = new SyncImporter();
    protected SyncExporter m_exporter = new SyncExporter();

    private bool m_initialized = false;


    public PwDatabase Database { get { return m_database; } }

    protected PwDatabase m_database = null;
    private List<SyncSource> m_syncSourceList = new List<SyncSource>();

    public event UpdatedEventHandler ChangedDB;

    public SyncMaster() {
      m_importer.Imported += NotifyAboutUpdates;
    }

    private void NotifyAboutUpdates(object sender, PwGroup group) {
      if (ChangedDB != null) ChangedDB.Invoke(this, group);
    }

    public void Initialize(PwDatabase database) {
      //do not activate the plugin if we open a DeltaContainer
      
      if (database.IsDeltaDatabase()) {
        return;
      }
      m_initialized = true;
      m_database = database;

      //====================== autocreating the neccassary groups ==================================
      m_database.GetExportGroup();
      m_database.GetImportGroup();
    }

    public void Export() {
      if (!m_initialized) {
        return;
      }
      m_exporter.Export(m_database);
    }

    /// <summary>
    /// The function we have to call from the outside to trigger any tests we have to
    /// make after some changes to the given database, so we can ensure full functionality
    /// </summary>
    /// <param name="database">The database we should work on.</param>
    public void RefeshSourcesList() {
      Debug.Assert(m_initialized);
      Debug.Assert(m_database != null);
      if (!m_initialized || m_database == null) {
        return;
      }

      PwGroup importGroup = m_database.GetImportGroup();
      PwObjectList<PwEntry> activeSources = importGroup.GetEntries(true);
      // remove old/invalid sources
      foreach (SyncSource source in m_syncSourceList.ToArray()) {
        //don't touch sources of closed tabs!
        if (source.DestinationDB != m_database) {
          // The database where the source is configured in is not a target for the source!
          // WTF: Why do we keep it in the DB?
          continue;
        }
        bool isActive = false;
        foreach (PwEntry entry in activeSources) {
          if (source.IsSimilar(entry, m_database) || source.IsSimilar(entry, m_database)) {
            isActive = true;
            break;
          }
        }
        if (!isActive) {
          source.StopWatch();
          source.Changed -= m_importer.Import;
          m_syncSourceList.Remove(source);
        }
      }

      //look for new sources
      foreach (PwEntry entry in activeSources) {
        if (entry.IsValidSource() && !SouceListContains(entry)) {
          //maybe only an update is needed
          SyncSource source = GetSourceRepresentedBy(entry);
          if (null != source && !source.IsEqual(entry, m_database)) {
            source.Key = SyncSource.CreateKeyFor(entry);
            source.StartWatch();
          }   //a syncSource without a Pasword that could be used as Key will be ignored!
          else if (entry.Strings.ReadSafe(KeeShare.PasswordField) != "") {
            //create a new source otherwise
            SyncSource src = new SyncSource(entry, m_database);
            src.Changed += m_importer.Import;
            src.StartWatch();
            m_syncSourceList.Add(src);
          }
        }
      }
    }

    /// <summary>
    /// The function checks if the actual syncSourceList contains a SyncSource that
    /// is similar to a syncSource that is represented through the given entry.
    /// That means, if we would use that entry and the given db to create a new SyncSource,
    /// that SyncSource would represent a SyncSource like one of the allready existing
    /// SyncSources in our list, except of the Password. That is interesting for us, because
    /// that way we can identify a SyncSource with a new Password.
    /// </summary>
    /// <param name="entry">The PwEntry from our db that should represent a SyncSource.</param>
    /// <returns>True if our list conatins a similar SyncSource allready.</returns>
    private SyncSource GetSourceRepresentedBy(PwEntry entry) {
      foreach (SyncSource source in m_syncSourceList) {
        if (source.IsSimilar(entry, m_database)) {
          return source;
        }
      }
      return null;
    }

    /// <summary>
    /// The function checks if the actual syncSourceList contains a SyncSource that
    /// is equal to a syncSource that is represented through the given entry.
    /// That means, if we would use that entry and the given db to create a new SyncSource,
    /// that SyncSource would represent exactly the same SyncSource like one of the allready
    /// existing SyncSources in our list.
    /// </summary>
    /// <param name="entry">The PwEntry from our db that should represent a SyncSource.</param>
    /// <returns>True if our list conatins that SyncSource allready.</returns>
    private bool SouceListContains(PwEntry entry) {
      foreach (SyncSource source in m_syncSourceList) {
        if (source.IsEqual(entry, m_database)) {
          return true;
        }
      }
      return false;
    }

    /// <summary>
    /// The function creates a new PwGroup that represents an export path.
    /// All userProxies that will be placed in that group means taht this
    /// user will use this export path too.
    /// </summary>
    /// <param name="folderName">The path to the folder in your filesystem that should be used
    /// as export destination.</param>
    /// <returns><c>ChangeFlags.CommonChange</c> if the function has made any changes to the 
    /// actual database structure (means if we added the expPath). 0 if the expPath allready exists
    /// and we don't have to make any changes anymore.</returns>
    public Changes AddExportPath(string folderName) {
      //is it a valid path?
      if (!Directory.Exists(folderName)) {
        return Changes.None;
      }
      //check if allready exists
      PwGroup exportGroup = m_database.GetExportGroup();
      foreach (PwGroup exp in exportGroup.GetGroups(false)) {
        if (exp.Name == folderName) {
          return Changes.None;
        }
      }

      //create new export path
      PwGroup newExport = new PwGroup(true, true, folderName, PwIcon.NetworkServer);
      newExport.SetParent(exportGroup);
      return Changes.GroupCreated;
    }

    /// <summary>
    /// The function creates a new PwEntry that represents an import source.
    /// </summary>
    /// <param name="fileName">The path to the file in your filesystem that should be used
    /// as import source.</param>
    /// <returns><c>ChangeFlags.CommonChange</c> if the function has made any changes to the 
    /// actual database structure (means if we added he impSrc). 0 if the impSrc allready exists
    /// and we don't have to make any changes anymore.</returns>
    public Changes AddImportPath(string fileName) {
      //is it a valid path to a file?
      if (!File.Exists(fileName)) {
        return Changes.None;
      }
      //check if allready exists
      PwGroup importGroup = m_database.GetImportGroup();
      foreach (PwEntry src in importGroup.GetEntries(true)) {
        if (src.Strings.ReadSafe(KeeShare.SourcePathField) == fileName) {
          return Changes.None;
        }
      }

      PwGroup newImportGroup = new PwGroup(true, true, fileName, PwIcon.NetworkServer);
      newImportGroup.SetParent(importGroup);
      PwEntry newImportSource = new PwEntry(true, true);
      newImportSource.Strings.Set(KeeShare.TitleField, new ProtectedString(false, fileName));
      newImportSource.Strings.Set(KeeShare.SourcePathField, new ProtectedString(false, fileName));
      newImportSource.SetParent(newImportGroup);
      return Changes.GroupCreated;

    }
  }
}
