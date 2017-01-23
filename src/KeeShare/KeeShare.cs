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
using KeePassLib.Interfaces;
using KeePassLib.Serialization;
using KeeShare.Properties;
using System;
using System.Collections.Generic;

namespace KeeShare {
  /// <summary>
  /// Holds magic strings and common needed methods for the plugin
  /// </summary>
  public class KeeShare {
    public static string CustomDataKey { get { return "com.hicknhack-software.KeeShare"; } }

    public static string UuidLinkField { get { return Settings.Default.StringFieldUidLink; } }

    public static string SourcesGroupName { get { return Settings.Default.SourcesGroupName; } }
    public static string SyncGroupName { get { return Settings.Default.SyncFolderName; } }
    public static string ExportGroupName { get { return Settings.Default.ExportGroupName; } }
    public static string ImportGroupName { get { return Settings.Default.ImportGroupName; } }

    public static string LastExportField { get { return Settings.Default.StringFieldLastExport; } }
    public static string SourcePathField { get { return Settings.Default.StringFieldSrcPath; } }

    public static string UsersGroupName { get { return Settings.Default.UserGroupName; } }
    public static string GroupsGroupName { get { return Settings.Default.GroupGroupName; } }

    public static string SynchronizationSourceField { get { return "KeeShareSynchronizationSourceField"; } }
    public static string TitleField { get { return PwDefs.TitleField; } }
    public static string PasswordField { get { return PwDefs.PasswordField; } }



    [Flags]
    public enum AttributeFlags : uint {
      None = 0,
      /* db scope */
      IsDeltaDatabase = 1 << 0, // use in CustomData on db, set if database is delata database
      IsKeeShareEnabled = 1 << 1, // use in CustomData on db, set if database can be used via keeshare
      IsTemporaryDatabase = 1 << 2, // use in CustomData on db, set if database is temp database
      /* group scope */
      IsSyncGroup = 1 << 3,
      IsExportGroup = 1 << 4,
      IsImportGroup = 1 << 5,
      IsUserGroup = 1 << 6,
      IsGroupGroup = 1 << 7,
      /* entry scope */
      IsUser = 1 << 8,
      IsGroup = 1 << 9
    }

    // Until now, there seems no need to implement the plugin protection in a thread safe way, but
    // in need it should be sufficient to change this variable to a lock and exit the protection 
    // when the caller cannot aquire the lock 
    private bool m_ignoreEvents = false;

    //UserManager conatains the user-functions
    private TreeManager m_treeManager = new TreeManager();
    private SyncMaster m_syncMaster = new SyncMaster();

    private Dictionary<IOConnectionInfo, PwDatabase> m_connections = new Dictionary<IOConnectionInfo, PwDatabase>();


    private delegate void ReleaseProotectedSection();
    public event UpdatedEventHandler Changed;
    private event ReleaseProotectedSection ProtectedSectionFinished;

    public KeeShare() {
      m_syncMaster.ChangedDB += OnDbChanged;
      // We need to wait for all events to be processed which were triggered during our own operation
      // else we may react to our own changes (Problem: ExtensionMethods.DuplicateTo with setParent  
      // which triggers Group/Entry moved events because the clone inherits the original parent group)
      // Alternative solution stategy for this problem would be to temporarily unregister the event 
      // handlers to prevent interference
      ProtectedSectionFinished += OnProtectedSectionFinished;
    }

    private void OnDbChanged(object sender, PwGroup group) {
      if (Changed != null) {
        Changed.Invoke(this, group.GetRootGroup());
      }
    }

    private bool IsProtected() {
      return m_ignoreEvents;
    }

    private void ProtectedSectionEntered() {
      m_ignoreEvents = true;
      //System.Diagnostics.Debug.WriteLine(">> Entered Protected Section");
    }

    private void OnProtectedSectionFinished() {
      m_ignoreEvents = false;
      //System.Diagnostics.Debug.WriteLine(">> Left Protected Section");
    }

    /// <summary>
    /// Executes the section passed using <paramref>call</paramref> only if the plugin does not already entered a protected section
    /// this prevents from updating after inserts/deletes executed by the plugin itself
    /// </summary>
    /// <param name="call"></param>
    private Changes ProtectedSection(Func<Changes> call) {
      if (IsProtected()) {
        return Changes.None;
      }
      ProtectedSectionEntered();
      try {
        return call();
      }
      finally {
        ProtectedSectionFinished();
      }
    }

    /// <summary>
    /// Executes the section passed using <paramref>call</paramref> only if the plugin does not already entered a protected section
    /// this prevents from updating after inserts/deletes executed by the plugin itself
    /// </summary>
    /// <param name="call"></param>
    private void ProtectedSection(Action call) {
      if (IsProtected()) {
        return;
      }
      ProtectedSectionEntered();
      try {
        call();
      }
      finally {
        ProtectedSectionFinished();
      }
    }

    public bool IsInitialized() {
      return m_treeManager != null && m_syncMaster != null;
    }

    public Changes EnsureValidTree(PwDatabase database) {
      return ProtectedSection(() => {
        m_treeManager.Initialize(database);
        m_syncMaster.Initialize(database);
        Changes changes = m_treeManager.CorrectStructure();
        m_syncMaster.RefeshSourcesList();
        return changes;
      });
    }

    public bool Observes(PwDatabase database) {
      if (database != null) {
        foreach (var observedDatabase in m_connections.Values) {
          if (database == observedDatabase) {
            return true;
          }
        }
      }
      return false;
    }

    public PwDatabase FindDatabaseFor(object sender) {
      if (sender is IStructureItem) {
        var root = (sender as IStructureItem).GetRootGroup();
        foreach (var database in m_connections.Values) {
          if (database.RootGroup == root) {
            return database;
          }
        }
      }
      return null;
    }

    public Changes Register(PwDatabase database, IOConnectionInfo info) {
      return ProtectedSection(() => {
        m_treeManager.Initialize(database);
        m_syncMaster.Initialize(database);
        m_connections.Add(info, database);
        return Changes.GroupCreated;
      });
    }

    public void Unregister(IOConnectionInfo info) {
      ProtectedSection(() => {
        m_connections.Remove(info);
      });
    }

    public Changes Initialize(PwDatabase database) {
      return ProtectedSection(() => {
        m_treeManager.Initialize(database);
        m_syncMaster.Initialize(database);
        return Changes.GroupCreated;
      });
    }

    public Changes AddImportPath(string path) {
      return ProtectedSection(() => {
        return m_syncMaster.AddImportPath(path);
      });
    }

    public Changes AddExportPath(string path) {
      return ProtectedSection(() => {
        return m_syncMaster.AddExportPath(path);
      });
    }

    public void Export() {
      ProtectedSection(() => {
        m_syncMaster.Export();

      });
    }

  }
}
