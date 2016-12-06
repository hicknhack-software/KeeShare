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
using System.Diagnostics;
using System.Windows.Forms;
using KeePass.Forms;
using KeePass.Plugins;
using KeePassLib;
using KeePass.DataExchange;
using KeePassLib.Interfaces;

namespace KeeShare
{
    public sealed class KeeShareExt: Plugin
    {
        // The sample plugin remembers its host in this variable.
        private IPluginHost m_host = null;
        private KeeShare m_keeShare = null;

        private ToolStripSeparator m_groupMenuSeparator = null;
        private ToolStripSeparator m_toolsMenuSeperator = null;
        //context menu
        //groups
        private ToolStripMenuItem m_groupMenuKeeShareSubMenu = null;
        private ToolStripMenuItem m_groupMenuKeeShareAddExportFolder = null;
        private ToolStripMenuItem m_groupMenuKeeShareAddImportFolder = null;

        private ToolStripMenuItem m_toolsMenuKeeShareSubMenu = null;
        private ToolStripMenuItem m_toolsMenuKeeShareAcivatePlugin = null;
        private ToolStripMenuItem m_toolsMenuKeeShareDeacivatePlugin = null;

        private PwDatabase ActiveDatabase
        {
            // Sollte identisch mit m_host.MainWindow.ActiveDatabase sein
            get
            {
                Debug.Assert(m_host.Database == m_host.MainWindow.ActiveDatabase);
                return m_host.MainWindow.ActiveDatabase;
            }
        }

        private MainForm Window
        {
            get { return m_host.MainWindow; }
        }

        private PwGroup SelectedGroup
        {
            get { return m_host.MainWindow.GetSelectedGroup(); }
        }

        private void InjectContextMenuEntries()
        {
            m_groupMenuSeparator = new ToolStripSeparator();

            m_groupMenuKeeShareSubMenu = new ToolStripMenuItem();
            m_groupMenuKeeShareSubMenu.Text = "KeeShare";

            m_groupMenuKeeShareAddExportFolder = new ToolStripMenuItem();
            m_groupMenuKeeShareAddExportFolder.Text = "Add Export Destination";
            m_groupMenuKeeShareAddExportFolder.Click += OnGroupMenuAddExportFolder;
            m_groupMenuKeeShareSubMenu.DropDownItems.Add(m_groupMenuKeeShareAddExportFolder);

            m_groupMenuKeeShareAddImportFolder = new ToolStripMenuItem();
            m_groupMenuKeeShareAddImportFolder.Text = "Add Import Source";
            m_groupMenuKeeShareAddImportFolder.Click += OnGroupMenuAddImportFolder;
            m_groupMenuKeeShareSubMenu.DropDownItems.Add(m_groupMenuKeeShareAddImportFolder);

            ToolStripItemCollection tsGroupMenu = Window.GroupContextMenu.Items;
            tsGroupMenu.Add(m_groupMenuSeparator);
            tsGroupMenu.Add(m_groupMenuKeeShareSubMenu);
        }

        private void InjectToToolsMenu()
        {
            m_toolsMenuSeperator = new ToolStripSeparator();

            m_toolsMenuKeeShareSubMenu = new ToolStripMenuItem();
            m_toolsMenuKeeShareSubMenu.Text = "KeeShare";

            m_toolsMenuKeeShareAcivatePlugin = new ToolStripMenuItem();
            m_toolsMenuKeeShareAcivatePlugin.Text = "Activate KeeShare to the actual Database";
            m_toolsMenuKeeShareAcivatePlugin.Click += OnActivatePlugin;
            m_toolsMenuKeeShareSubMenu.DropDownItems.Add(m_toolsMenuKeeShareAcivatePlugin);

            m_toolsMenuKeeShareDeacivatePlugin = new ToolStripMenuItem();
            m_toolsMenuKeeShareDeacivatePlugin.Text = "Deactivate KeeShare on the actual Database";
            m_toolsMenuKeeShareDeacivatePlugin.Click += OnDeactivatePlugin;
            m_toolsMenuKeeShareSubMenu.DropDownItems.Add(m_toolsMenuKeeShareDeacivatePlugin);

            ToolStripItemCollection toolsMenu = Window.ToolsMenu.DropDownItems;
            toolsMenu.Add(m_toolsMenuSeperator);
            toolsMenu.Add(m_toolsMenuKeeShareSubMenu);
        }

        private void RegisterForChanges()
        {
            // We want a notification when the user tried to save the
            // current database
            Window.FileSaved += OnFileSaved;
            Window.FileClosed += OnFileClosed;
            Window.FileOpened += OnFileOpened;
            Window.FileCreated += OnFileCreated;

            ImportUtil.ImportSuccessful += OnImportFinished;

            PwEntry.EntryModified += OnNodeChanged;
            PwGroup.GroupModified += OnNodeChanged;

            PwGroup.GroupAdded += OnNodeChanged;
            PwGroup.GroupRemoved += OnNodeChanged;
            PwGroup.EntryAdded += OnNodeChanged;
            PwGroup.EntryRemoved += OnNodeChanged;

            m_keeShare.Changed += UpdateUI;
        }

        private void OnImportFinished(object sender, ImportedEventArgs e)
        {
            EnsurevalidTree(e.PwStorage);
        }

        private void RemoveFromContextMenu()
        {
            // WFT Inject is to GroupContextMenu - Remove from EntryContextMenu?
            // Remove all of our menu items
            ToolStripItemCollection tsMenu = Window.GroupContextMenu.Items;
            tsMenu.Remove(m_groupMenuSeparator);
            //group context menu
            tsMenu.Remove(m_groupMenuKeeShareAddExportFolder);
            tsMenu.Remove(m_groupMenuKeeShareAddImportFolder);
            tsMenu.Remove(m_groupMenuKeeShareSubMenu);
        }

        private void RemoveFromToolsMenu()
        {
            ToolStripItemCollection toolsMenu = Window.ToolsMenu.DropDownItems;
            toolsMenu.Remove(m_toolsMenuKeeShareSubMenu);
        }

        private void UnregisterFromChanges()
        {
            // Important! Remove event handlers!
            Window.FileSaved -= OnFileSaved;
            Window.FileOpened -= OnFileOpened;
            Window.FileCreated -= OnFileCreated;

            ImportUtil.ImportSuccessful -= OnImportFinished;

            PwEntry.EntryModified -= OnNodeChanged;
            PwGroup.GroupModified -= OnNodeChanged;

            PwGroup.GroupAdded -= OnNodeChanged;
            PwGroup.GroupRemoved -= OnNodeChanged;
            PwGroup.EntryAdded -= OnNodeChanged;
            PwGroup.EntryRemoved -= OnNodeChanged;

            m_keeShare.Changed -= UpdateUI;
        }

        /// <summary>
        /// The <c>Initialize</c> function is called by KeePass when
        /// you should initialize your plugin (create menu items, etc.).
        /// </summary>
        /// <param name="host">Plugin host interface. By using this
        /// interface, you can access the KeePass main window and the
        /// currently opened database.</param>
        /// <returns>You must return <c>true</c> in order to signal
        /// successful initialization. If you return <c>false</c>,
        /// KeePass unloads your plugin (without calling the
        /// <c>Terminate</c> function of your plugin).</returns>
        public override bool Initialize(IPluginHost host)
        {
            Debug.Assert( host != null );
            if( host == null )
            {
                return false;
            }
            m_host = host;
            m_keeShare = new KeeShare();

            InjectContextMenuEntries();
            InjectToToolsMenu();

            RegisterForChanges();
         
            return true; // Initialization successful
        }

        /// <summary>
        /// The <c>Terminate</c> function is called by KeePass when
        /// you should free all resources, close open files/streams,
        /// etc. It is also recommended that you remove all your
        /// plugin menu items from the KeePass menu.
        /// </summary>
        public override void Terminate()
        {
            RemoveFromContextMenu();
            RemoveFromToolsMenu();

            UnregisterFromChanges();
        }

        /// <summary>
        /// This function validates if the plugin is allowed to handel the active database.
        /// </summary>
        /// <returns>True if a special tag was set to the database, so we could identify it as a
        /// KeeShare-database</returns>
        private bool IsPluginActive()
        {
            return !IsActiveDbDeltaDb()
                && ActiveDatabase.IsOpen
                && ActiveDatabase.IsRegistered(KeeShare.PluginActivationId, KeeShare.PluginActivationTag);
        }

        private bool IsActiveDatabase(PwDatabase database)
        {
            return m_host.Database == database;
        }

        /// <summary>
        /// This function validates if the active database is a deltaContainer
        /// </summary>
        /// <returns>True if the active db is a deltaContainer</returns>
        private bool IsActiveDbDeltaDb()
        {
            return ActiveDatabase.IsOpen 
                && ActiveDatabase.IsRegistered(KeeShare.DeltaDatabaseId, KeeShare.DeltaDatabaseTag);
        }

        /// <summary>
        /// This function deactivates the plugin on the actual database
        /// </summary>
        /// <param name="sender"></param>
        /// <param name="e"></param>
        private void OnActivatePlugin(object sender, EventArgs e)
        {
            if( !ActiveDatabase.IsOpen || IsPluginActive() || IsActiveDbDeltaDb() )   
            {
                return;
            }
            //we activate the plugin by tagging the active db and initializing the managers
            bool registered = ActiveDatabase.Register( KeeShare.PluginActivationId, KeeShare.PluginActivationTag );
            Changes changes = m_keeShare.Initialize(ActiveDatabase)
                |  m_keeShare.Register(ActiveDatabase, ActiveDatabase.IOConnectionInfo);
            UpdateUI(ActiveDatabase.RootGroup, changes, registered);
        }

        /// <summary>
        /// This function handles the user-click on the menu item that
        /// deactivates the plugin for the active database
        /// </summary>
        /// <param name="sender"></param>
        /// <param name="e"></param>
        private void OnDeactivatePlugin(object sender, EventArgs e)
        {
            if( !ActiveDatabase.IsOpen || !IsPluginActive() || IsActiveDbDeltaDb())
            {
                return;
            }
            //we deactivate the plugin by untagging the database
            bool unregistered = ActiveDatabase.Unregister(KeeShare.PluginActivationId );
            m_keeShare.Unregister(ActiveDatabase.IOConnectionInfo);
            UpdateUI(ActiveDatabase.RootGroup, Changes.None, unregistered);
        }


        private void UpdateUI(PwGroup updateRoot, Changes changes, bool modified)
        {
            if (changes.HasFlag(Changes.None) && !modified)
            {
                return;
            }
            bool recreateTabBar = false;
            KeePass.UI.PwDocument select = null;
            bool updateEntryList = changes.HasFlag(Changes.ListDisplayChange | Changes.ListStructChange );
            bool updateGroupTree = changes.HasFlag(Changes.TreeDisplayChange | Changes.TreeStructureChange);
            PwGroup entrySource = null;
            m_host.MainWindow.UpdateUI(recreateTabBar, select, updateGroupTree, updateRoot, updateEntryList, entrySource, modified);
        }

   
        private void OnGroupMenuAddExportFolder(object sender, EventArgs e)
        {
            if(!IsPluginActive())
            {
                return;
            }

            FolderBrowserDialog folderBrowserDialog = new FolderBrowserDialog();
            DialogResult result = folderBrowserDialog.ShowDialog();
            if (result == DialogResult.OK)
            {
                Changes changes = m_keeShare.AddExportPath(folderBrowserDialog.SelectedPath);
                UpdateUI(ActiveDatabase.GetExportGroup(), changes, true);
            }
        }

        private void OnGroupMenuAddImportFolder(object sender, EventArgs e)
        {
            if (!IsPluginActive())
            {
                return;
            }

            OpenFileDialog openFileDialog = new OpenFileDialog();
            DialogResult result = openFileDialog.ShowDialog();
            if (result == DialogResult.OK)
            {
                Changes changes = m_keeShare.AddImportPath(openFileDialog.FileName);
                UpdateUI(ActiveDatabase.GetImportGroup(), changes, true);
            }
        }

        private void OnFileSaved(object sender, FileSavedEventArgs e)
        {
            if (!IsPluginActive() || !IsActiveDatabase(e.Database))
            {
                return;
            }
            //automatically trigger the export function of the syncMaster
            m_keeShare.Export();
        }

    

        private void OnFileClosed(object sender, FileClosedEventArgs e)
        {
            if (!IsPluginActive())
            {
                return;
            }
            m_keeShare.Unregister(e.IOConnectionInfo);
        }

        private void OnFileOpened(object sender, FileOpenedEventArgs e)
        {
            if (!IsPluginActive())
            {
                return;
            }
            Changes changes = m_keeShare.Register(e.Database, e.Database.IOConnectionInfo);
            // Initializing the plugin does not trigger a Modify in itself, only interacting with the plugin does
            UpdateUI(e.Database.GetExportGroup(), changes, false); 
        }

        private void OnFileCreated(object sender, FileCreatedEventArgs e)
        {
            if (!IsPluginActive())
            {
                return;
            }
            Changes changes = m_keeShare.Register(e.Database, e.Database.IOConnectionInfo);
            UpdateUI(e.Database.GetExportGroup(), changes, true);
        }

        //callback function for threadsafe UiUpdate after changing the database via the SyncMaster
        private delegate void UpdateUICallback(object sender, PwGroup group);

        private void UpdateUI(object sender, PwGroup group)
        {
            try
            {
                if( Window.InvokeRequired )
                {
                    // trigger OnDbChanged in the appropriate thread
                    UpdateUICallback odbc = new UpdateUICallback( UpdateUI );
                    Window.Invoke( odbc, new object[] { this, group } );
                }
                else
                {
                    //it is not sure, if the upate changed/imported a group, therefore we are 
                    //pessimistic and force an update of the list
                    UpdateUI(group, Changes.Arbitrary, true);
                }
            }
            catch (Exception e)
            {
                Debug.WriteLine( "Error during UpdateUI: " + e.Message.ToString() );
            }
        }

        private void EnsurevalidTree(PwDatabase database)
        {
            if (!IsPluginActive() || !m_keeShare.IsInitialized())
            {
                return;
            }
            if (!m_keeShare.Observes(database))
            {
                // KeePass checks the structure at some points (ie. after Save) using a deep copy of the database
                // which we don't want to update or modify
                return;
            }
            Changes changes = m_keeShare.EnsureValidTree(database);
            UpdateUI(database.RootGroup, changes, true);
        }

        private void OnNodeChanged(object sender, ObjectTouchedEventArgs args)
        {
            if (!IsPluginActive() || !m_keeShare.IsInitialized())
            {
                return;
            }
            PwDatabase database = m_keeShare.FindDatabaseFor(sender);
            if (!m_keeShare.Observes(database))
            {
                // KeePass checks the structure at some points (ie. after Save) using a deep copy of the database
                // which we don't want to update or modify
                return;
            }
            PwDatabase database2 = m_keeShare.FindDatabaseFor(sender);
            Changes changes = m_keeShare.EnsureValidTree(database);
            UpdateUI(database.RootGroup, changes, true);
        }
    }
}
