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


using NUnit.Framework;
using KeePassLib;
using KeeShare;
using KeePassLib.Collections;
using System.Linq;
using System.IO;
using KeePassLib.Serialization;
using KeePassLib.Keys;

namespace KeeShareTest
{
    // MISSING TEST CASES
    //      NEGATIVE TESTS FOR MISSING EXPORT DIRECTORIES - MAINLY FOR DOCUMENTATION
    //      EXPORT USER GROUP
    //      SHARE TO USER GROUP
    //      IMPORT OF KEY ALREADY EXISTING TO CHECK FOR CYCLIC DEPENDENCY PROBLEMS
	[TestFixture]
	class SyncMasterUnitTest
	{
        const string STANDARD_PASSWORD = "abcde";
        PwDatabase m_database = null;
		TreeManagerAccessor m_treeManager = null;
		SyncMasterAccessor m_syncManager = null;
        CompositeKey m_standardKey = null;

        //critical Uuids
        PwUuid Uuid1, Uuid2, Uuid3, Uuid4, Uuid5, Uuid6;

        private void SetupDatabaseAndTree()
        {
            //standard for all tests is an standard database with the rootGroup and some PwEntries
            m_database = TestHelper.CreateDatabase();

            m_treeManager = new TreeManagerAccessor();
            m_syncManager = new SyncMasterAccessor();
            m_syncManager.Initialize(m_database);
            m_treeManager.Initialize(m_database);
        }

        private void FillInFixture()
        {
            PwGroup rootGroup = m_database.RootGroup;

            m_treeManager.CreateNewUser("mrX");
            m_treeManager.CreateNewUser("mrY");
            m_standardKey = SyncSource.CreateKeyFor(STANDARD_PASSWORD);

            PwEntry mrX = TestHelper.GetUserRootNodeByNameFor(m_database, "mrX");
            PwEntry mrY = TestHelper.GetUserRootNodeByNameFor(m_database, "mrY");
            mrX.SetPassword(STANDARD_PASSWORD);
            mrY.SetPassword(STANDARD_PASSWORD);
            PwGroup mrXhome = m_database.GetUsersGroup().Groups.GetAt(0);

            //normal entries
            PwEntry normalEntry1 = new PwEntry(true, false);
            normalEntry1.SetTitle("normalEntry1");
            Uuid1 = normalEntry1.Uuid;
            PwEntry normalEntry2 = new PwEntry(true, false);
            normalEntry2.SetTitle("normalEntry2");
            Uuid2 = normalEntry2.Uuid;
            PwEntry normalEntry3 = new PwEntry(true, false);
            normalEntry3.SetTitle("normalEntry3");
            Uuid3 = normalEntry3.Uuid;
            PwEntry normalEntry4 = new PwEntry(true, false);
            normalEntry4.SetTitle("normalEntry4");
            Uuid4 = normalEntry4.Uuid;
            PwEntry normalEntry5 = new PwEntry(true, false);
            normalEntry5.SetTitle("normalEntry5");
            Uuid5 = normalEntry5.Uuid;
            PwEntry normalEntry6 = new PwEntry(true, false);
            normalEntry6.SetTitle("normalEntry6");
            Uuid6 = normalEntry6.Uuid;

            //pwdProxies
            PwEntry pwdProxyTo1 = PwNode.CreateProxyNode(normalEntry1);
            PwEntry pwdProxyTo3 = PwNode.CreateProxyNode(normalEntry3);

            //userProxies
            PwEntry userProxyToMrX = PwNode.CreateProxyNode(mrX);

            PwGroup grp1 = new PwGroup(true, true, "grp1", PwIcon.BlackBerry);

            rootGroup.AddEntry(normalEntry1, true);
            rootGroup.AddEntry(normalEntry2, true);
            rootGroup.AddEntry(normalEntry3, true);
            rootGroup.AddGroup(grp1, true);

            grp1.AddEntry(normalEntry4, true);
            grp1.AddEntry(normalEntry5, true);
            grp1.AddEntry(userProxyToMrX, true);
            grp1.AddEntry(pwdProxyTo1, true);

            mrXhome.AddEntry(normalEntry6, true);
            mrXhome.AddEntry(pwdProxyTo3, true);
            Assert.AreEqual(13, rootGroup.GetEntries(true).UCount);
        }

        private string GetTestPath()
        {
            return Directory.GetCurrentDirectory() + @"\KeeShareTestFiles\SyncMaster\";
        }

		[SetUp]
		public void TestInit()
		{
            TestHelper.CleanFilesystem(GetTestPath());
            SetupDatabaseAndTree();
            FillInFixture();
		}

		[TearDown]
		public void TestCleanup()
		{
			m_database = null;
			m_syncManager = null;
            m_treeManager = null;
		}

        [Test]
        public void SharedFoldersCollectsAllSharedFoldersForAuser()
        {
            PwEntry mrX = TestHelper.GetUserRootNodeFor(m_database, 0);
            Assert.AreEqual("mrX", mrX.Strings.ReadSafe(KeeShare.KeeShare.TitleField));
            //according to our testDatabase we want to ensure that GetSharedFolders(mrX)
            //returns a list of groups with only two members: "grp1" and the home of "mrX"
            PwObjectList<PwGroup> sharedFolders = m_syncManager.GetSharedFolders(mrX);
            Assert.AreEqual(2, sharedFolders.UCount);
            Assert.AreEqual("grp1", sharedFolders.GetAt(0).Name);
            Assert.AreEqual("mrX", sharedFolders.GetAt(1).Name);
        }

        [Test]
        public void EnsureAllSharedFoldersArePartOfDeltaDB()
        {
            PwEntry mrX = TestHelper.GetUserRootNodeFor(m_database, 0);
            Assert.AreEqual("mrX", mrX.Strings.ReadSafe(KeeShare.KeeShare.TitleField));
            //according to our testDatabase we want to ensure that GetSharedFolders(mrX)
            //returns a list of groups with only two members: "grp1" and the home of "mrX"
            PwObjectList<PwGroup> sharedFolders = m_syncManager.GetSharedFolders(mrX);
            PwDatabase deltaDB = m_syncManager.CreateDeltaDb(sharedFolders);
            //the deltaDB must exactly hold the following items in exactly the following structure:
            //overall entriecount: 5
            //rootGroup.entries: "normalEntry1" "normalEntry3" "normalEntry6"
            //grp1.etries: "normalEntry4" normalEntry5"
            Assert.AreEqual(5, deltaDB.RootGroup.GetEntries(true).UCount);
            //searching non-recursive ensures that the entries are located in the rootGroup
            Assert.IsNotNull(deltaDB.RootGroup.FindEntry(Uuid1, false));
            Assert.IsNotNull(deltaDB.RootGroup.FindEntry(Uuid3, false));
            Assert.IsNotNull(deltaDB.RootGroup.FindEntry(Uuid6, false));
            PwEntry entry4 = deltaDB.RootGroup.FindEntry(Uuid4, true);
            PwEntry entry5 = deltaDB.RootGroup.FindEntry(Uuid5, true);
            Assert.IsNotNull(entry4);
            Assert.IsNotNull(entry5);
            Assert.AreEqual("grp1", entry4.ParentGroup.Name);
            Assert.AreEqual("grp1", entry5.ParentGroup.Name);
        }

        [Test]
        public void SharedFoldersCollectsOnlySharedFolders()
        {
            PwEntry mrY = TestHelper.GetUserRootNodeFor(m_database, 1);
            Assert.AreEqual("mrY", mrY.Strings.ReadSafe(KeeShare.KeeShare.TitleField));
            PwObjectList<PwGroup> sharedFoldersY = m_syncManager.GetSharedFolders(mrY);
            Assert.AreEqual(1, sharedFoldersY.UCount);
            Assert.AreEqual("mrY", sharedFoldersY.GetAt(0).Name);
        }

		[Test]
		public void EnsureOnlySharedFoldersArePartOfDeltaDB()
		{
            PwEntry mrY = TestHelper.GetUserRootNodeFor(m_database, 1);
            Assert.AreEqual("mrY", mrY.Strings.ReadSafe(KeeShare.KeeShare.TitleField));
            PwObjectList<PwGroup> sharedFoldersY = m_syncManager.GetSharedFolders(mrY);
            PwDatabase deltaDBY = m_syncManager.CreateDeltaDb( sharedFoldersY );
			Assert.AreEqual( 0, deltaDBY.RootGroup.GetEntries( true ).UCount );
		}

        [Test]
        public void ShouldExportToTargets()
        {
            //we change the password which is used to encrypt the delta container so we can later access the delta container
            //more easily.
            PwEntry mrX = TestHelper.GetUserRootNodeFor(m_database, 0);
            //the first autoExport only checks if there is a delta container allready and if not it will export one
            //in our case there should be no existing container so a new one will be created.
            var exportFolder = m_database.GetExportGroup();
            Assert.IsTrue(0 == exportFolder.Groups.UCount);
            string exportPath = GetTestPath();
            
            m_syncManager.AddExportPath(exportPath);
            var exportGroup = exportFolder.Groups.GetAt(0);

            exportGroup.AddEntry(PwNode.CreateProxyNode(mrX), true);

            string exportFile = exportPath + SyncSource.FileNameFor(mrX) + SyncExporter.FileExtension;

            Assert.IsFalse(File.Exists(exportFile));

            m_syncManager.RefeshSourcesList();
            m_syncManager.Export();

            mrX = TestHelper.GetUserRootNodeFor(m_database, 0);
            Assert.AreEqual("mrX", mrX.Strings.ReadSafe(KeeShare.KeeShare.TitleField));
            
            Assert.IsTrue(File.Exists(exportFile));

            //now we open the creted delta container and verify the contend
            PwDatabase deltaDB = new PwDatabase();

            Assert.DoesNotThrow(delegate {
                deltaDB.Open(IOConnectionInfo.FromPath(exportFile), m_standardKey, null);
            });

            Assert.AreEqual(5, deltaDB.RootGroup.GetEntries(true).UCount);
            Assert.AreEqual(3, deltaDB.RootGroup.Entries.UCount);
            Assert.AreEqual("grp1", deltaDB.RootGroup.Groups.GetAt(0).Name);
            Assert.AreEqual(2, deltaDB.RootGroup.Groups.GetAt(0).Entries.UCount);
            //now we will test in detail if there are only the expected entries in the created delta container
            Assert.AreEqual(Uuid1, deltaDB.RootGroup.Entries.GetAt(0).Uuid);
            Assert.AreEqual(Uuid3, deltaDB.RootGroup.Entries.GetAt(2).Uuid);
            Assert.AreEqual(Uuid6, deltaDB.RootGroup.Entries.GetAt(1).Uuid);
            Assert.AreEqual(Uuid4, deltaDB.RootGroup.Groups.GetAt(0).Entries.GetAt(0).Uuid);
            Assert.AreEqual(Uuid5, deltaDB.RootGroup.Groups.GetAt(0).Entries.GetAt(1).Uuid);
            Assert.AreEqual("normalEntry1", deltaDB.RootGroup.Entries.GetAt(0).GetTitle());
            deltaDB.Close();
        }

        [Test]
        public void ShouldIgnoreUsersWithoutTargets()
        {
            PwEntry mrY = m_database.GetUsersGroup().Groups.GetAt(1).Entries.GetAt(0);
            Assert.AreEqual("mrY", mrY.Strings.ReadSafe(KeeShare.KeeShare.TitleField));
            string exportPath = GetTestPath();
            string exportFile = exportPath + SyncSource.FileNameFor( mrY ) + SyncExporter.FileExtension;
            Assert.IsFalse(File.Exists(exportFile));

            m_syncManager.RefeshSourcesList();
            m_syncManager.Export();

            Assert.IsFalse(File.Exists(exportFile));
        }

        [Test]
        public void ShouldExportAfterChangedContent()
        {
            PwEntry mrX = TestHelper.GetUserRootNodeFor(m_database, 0);

            //the first autoExport only checks if there is a delta container allready and if not it will export one
            //in our case there should be no existing container so a new one will be created.
            string exportPath = GetTestPath();
            PwGroup exportGroup = new PwGroup(true, true, exportPath, PwIcon.Apple);
            m_database.GetExportGroup().AddGroup(exportGroup, true);
            exportGroup.AddEntry(PwNode.CreateProxyNode(mrX), true);

            string exportFile = exportPath + SyncSource.FileNameFor(mrX) + SyncExporter.FileExtension;

            Assert.IsFalse(File.Exists(exportFile));

            m_syncManager.RefeshSourcesList();
            m_syncManager.Export();

            mrX = TestHelper.GetUserRootNodeFor(m_database, 0);
            Assert.AreEqual("mrX", mrX.GetTitle());

            Assert.IsTrue(File.Exists(exportFile));

            //now we will change a password that is shared to mrX and then trigger the AutoExport method
            //like it will happen on any OnChangeEvent. After that again we validate the data in the export container.
            PwEntry entry1 = m_database.RootGroup.FindEntry(Uuid1, true);
            entry1.SetTitle("new title");
            //due to the fact that the UnitTest is way faster than userIneraction we have to manipulate the lastModTimestamp
            //because if we don't do that the um.Update() method will maybe use another value to update all references and
            //then we will have the old title in the stringField
            TestHelper.SimulateTouch(entry1);
            //now we run the update methods that will be triggered on every UiChangeEvent
            m_treeManager.CorrectStructure();
            m_syncManager.RefeshSourcesList();
            //the autoexport method was triggered by in import or OnSaveEvent only so we have to trigger it manually here

            m_syncManager.Export();

            PwDatabase deltaDB = new PwDatabase();

            Assert.DoesNotThrow(delegate {
                deltaDB.Open(IOConnectionInfo.FromPath(exportFile), m_standardKey, null);
            });
            //as before we want to have the same content except that entry1 should now have a new title!
            Assert.AreEqual(5, deltaDB.RootGroup.GetEntries(true).UCount);
            Assert.AreEqual(3, deltaDB.RootGroup.Entries.UCount);
            Assert.AreEqual("grp1", deltaDB.RootGroup.Groups.GetAt(0).Name);
            Assert.AreEqual(2, deltaDB.RootGroup.Groups.GetAt(0).Entries.UCount);
            //now we will test in detail if there are only the expected entries in the created delta container
            Assert.AreEqual(Uuid1, deltaDB.RootGroup.Entries.GetAt(0).Uuid);
            Assert.AreEqual(Uuid3, deltaDB.RootGroup.Entries.GetAt(2).Uuid);
            Assert.AreEqual(Uuid6, deltaDB.RootGroup.Entries.GetAt(1).Uuid);
            Assert.AreEqual(Uuid4, deltaDB.RootGroup.Groups.GetAt(0).Entries.GetAt(0).Uuid);
            Assert.AreEqual(Uuid5, deltaDB.RootGroup.Groups.GetAt(0).Entries.GetAt(1).Uuid);
            Assert.AreEqual("new title", deltaDB.RootGroup.Entries.GetAt(0).GetTitle());
            deltaDB.Close();
        }


        [Test]
        public void ShouldOnlyExportToCurrentSharedUsers()
        {
            m_treeManager.Initialize(m_database);
            var exportPath = GetTestPath();

            m_syncManager.AddExportPath(exportPath);
            var exportGroup = m_database.GetExportGroup().Groups.GetAt( 0 ) ;


            m_treeManager.CreateNewUser("Adam");
            m_treeManager.CreateNewUser("Eva");
            var userAdam = TestHelper.GetUserRootNodeByNameFor(m_database, "Adam");
            var userEva = TestHelper.GetUserRootNodeByNameFor(m_database, "Eva");
            userAdam.SetPassword(STANDARD_PASSWORD);
            userEva.SetPassword(STANDARD_PASSWORD);

            m_database.RootGroup.AddEntry(PwNode.CreateProxyNode(userAdam), true);
            m_database.RootGroup.AddEntry(PwNode.CreateProxyNode(userEva), true);

            exportGroup.AddEntry(PwNode.CreateProxyNode(userAdam), true);
            exportGroup.AddEntry(PwNode.CreateProxyNode(userEva), true);
            m_treeManager.CorrectStructure();

            string exportFileAdam = exportPath + SyncSource.FileNameFor(userAdam) + SyncExporter.FileExtension;
            string exportFileEva = exportPath + SyncSource.FileNameFor(userEva) + SyncExporter.FileExtension;

            Assert.IsFalse(File.Exists(exportFileAdam));
            Assert.IsFalse(File.Exists(exportFileEva));
            
            m_syncManager.Export();
            // TODO CK: At this point it may be possible that the files are not created - we need to wait for the filesystem to respond - maybe using a delay?
            Assert.IsTrue(File.Exists(exportFileAdam));
            Assert.IsTrue(File.Exists(exportFileEva));

            var homeAdam = TestHelper.GetUserHomeNodeByNameFor(m_database, "Adam");
            homeAdam.ParentGroup.Groups.Remove(homeAdam);
            var trash = m_database.RootGroup.FindGroup(m_database.RecycleBinUuid, true);
            trash.AddGroup(homeAdam, true);
            trash.DeleteAllObjects(m_database);
            //update should delete all references to the non existing user

            m_treeManager.CorrectStructure();

            var changedEntry = m_database.RootGroup.Entries.GetAt(0);
            changedEntry.SetTitle("Changed");
            TestHelper.SimulateTouch(changedEntry);

            m_syncManager.Export();

            TestHelper.DelayAction();

            var deltaDBAdamReexport = new PwDatabase();
            deltaDBAdamReexport.Open(IOConnectionInfo.FromPath(exportFileAdam), m_standardKey, null);
            Assert.AreEqual(Uuid1, deltaDBAdamReexport.RootGroup.Entries.GetAt(0).Uuid);
            Assert.AreNotEqual("Changed", deltaDBAdamReexport.RootGroup.Entries.GetAt(0).GetTitle());
            deltaDBAdamReexport.Close();
            var deltaDBEvaReexport = new PwDatabase();
            deltaDBEvaReexport.Open(IOConnectionInfo.FromPath(exportFileEva), m_standardKey, null);
            Assert.AreEqual(Uuid1, deltaDBEvaReexport.RootGroup.Entries.GetAt(0).Uuid);
            Assert.AreEqual("Changed", deltaDBEvaReexport.RootGroup.Entries.GetAt(0).GetTitle());
            deltaDBEvaReexport.Close();
        }

        [Test]
        public void ShouldNotExportKeeShareNodes()
        {
            m_treeManager.Initialize(m_database);
            var exportPath = GetTestPath();

            m_syncManager.AddExportPath(exportPath);
            var userMrX = TestHelper.GetUserRootNodeByNameFor(m_database, "mrX");
            var userMrY = TestHelper.GetUserRootNodeByNameFor(m_database, "mrY");
            userMrY.SetPassword(STANDARD_PASSWORD);

            m_database.GetExportGroup().Groups.GetAt(0).AddEntry(PwNode.CreateProxyNode(userMrY), true);

            m_database.RootGroup.AddEntry(PwNode.CreateProxyNode(userMrX), true);

            m_treeManager.CorrectStructure();

            m_database.GetUserHomeFor(userMrY).AddEntry(PwNode.CreateProxyNode(userMrX), true);
            m_database.GetUserHomeFor(userMrX).AddEntry(PwNode.CreateProxyNode(userMrY), true);

            string exportFile = exportPath + SyncSource.FileNameFor(userMrY) + SyncExporter.FileExtension;

            Assert.IsFalse(File.Exists(exportFile));

            m_syncManager.Export();

            TestHelper.DelayAction();

            Assert.IsTrue(File.Exists(exportFile));

            var deltaDBAdamReexport = new PwDatabase();
            deltaDBAdamReexport.Open(IOConnectionInfo.FromPath(exportFile), m_standardKey, null);
            foreach( var entry in deltaDBAdamReexport.RootGroup.GetEntries( true ))
            {
                Assert.AreNotEqual(userMrX.GetTitle(), entry.GetTitle());
            }
            foreach( var group in deltaDBAdamReexport.RootGroup.GetGroups(true))
            {
                Assert.AreNotEqual(userMrX.GetTitle(), group.Name);
            }
        }

        [Test]
        public void ShouldExportImportedNodes()
        {
            var importDatabase = TestHelper.CreateDatabase();
            var importedEntry = new PwEntry(true, true);
            importedEntry.SetTitle("ImportedEntry");
            var importedGroup = new PwGroup(true, true);
            importedGroup.Name = "ImportedGroup";
            importedGroup.AddEntry(importedEntry, true);
            importDatabase.RootGroup.AddGroup(importedGroup, true);

            var exportPath = GetTestPath();

            m_syncManager.AddExportPath(exportPath);
            var userMrX = TestHelper.GetUserRootNodeByNameFor(m_database, "mrX");
            
            m_database.GetExportGroup().Groups.GetAt(0).AddEntry(PwNode.CreateProxyNode(userMrX), true);

            m_database.RootGroup.AddEntry(PwNode.CreateProxyNode(userMrX), true);
            var existingEntry = new PwEntry(true, true);
            existingEntry.SetTitle("ExistingEntry");
            m_database.RootGroup.AddEntry(existingEntry, true);
            m_treeManager.CorrectStructure();

            string exportFile = exportPath + SyncSource.FileNameFor(userMrX) + SyncExporter.FileExtension;
            Assert.IsFalse(File.Exists(exportFile));

            Assert.AreEqual(0, m_database.RootGroup.GetEntries(true).Count(e => e.GetTitle() == "ImportedEntry"));
            Assert.AreEqual(0, m_database.RootGroup.GetGroups(true).Count(g => g.Name == "ImportedGroup"));

            m_syncManager.Export();

            Assert.IsTrue(File.Exists(exportFile));

            var importer = new SyncImporterAccessor();
            importer.MergeInAccessor(m_database, importDatabase);

            Assert.AreEqual(1, m_database.RootGroup.GetEntries(true).Count(e => e.GetTitle() == "ImportedEntry"));
            Assert.AreEqual(1, m_database.RootGroup.GetGroups(true).Count(g => g.Name == "ImportedGroup"));

            m_syncManager.Export();

            Assert.IsTrue(File.Exists(exportFile));

            var deltaDBUpdated = new PwDatabase();
            deltaDBUpdated.Open(IOConnectionInfo.FromPath(exportFile), m_standardKey, null);
            Assert.AreEqual(1, deltaDBUpdated.RootGroup.GetEntries(true).Count(e => e.GetTitle() == "ImportedEntry"));
            Assert.AreEqual(1, deltaDBUpdated.RootGroup.GetGroups(true).Count(g => g.Name == "ImportedGroup"));
            deltaDBUpdated.Close();
        }

        [Test]
        public void ShouldHandleCyclesOfNodesInImportAndExport()
        {
            var exportPath = GetTestPath();
            m_syncManager.AddExportPath(exportPath);

            var userMrX = TestHelper.GetUserRootNodeByNameFor(m_database, "mrX");
            m_database.GetExportGroup().Groups.GetAt(0).AddEntry(PwNode.CreateProxyNode(userMrX), true);

            var existingEntry = new PwEntry(true, true);
            existingEntry.SetTitle("Entry Version 1");
            m_database.RootGroup.AddEntry(existingEntry, true);
            m_database.RootGroup.AddEntry(PwNode.CreateProxyNode(userMrX), true);

            m_treeManager.CorrectStructure();

            string exportFile = exportPath + SyncSource.FileNameFor(userMrX) + SyncExporter.FileExtension;
            Assert.IsFalse(File.Exists(exportFile));

            m_syncManager.Export();

            var deltaDBInitial = new PwDatabase();
            deltaDBInitial.Open(IOConnectionInfo.FromPath(exportFile), m_standardKey, null);
            Assert.AreEqual(1, deltaDBInitial.RootGroup.GetEntries(true).Count(e => e.GetTitle() == "Entry Version 1"));
            foreach(var entry in deltaDBInitial.RootGroup.GetEntries(true))
            {
                entry.SetTitle("Changed");
            }
            deltaDBInitial.Save(null);
            deltaDBInitial.Close();

            m_syncManager.AddImportPath(exportFile);
            m_database.GetImportGroup().Groups.GetAt(0).Entries.GetAt(0).SetPassword(userMrX.Strings.ReadSafe(KeeShare.KeeShare.PasswordField));

            m_syncManager.RefeshSourcesList();
            // Node normalEntry6 is within the user home and is relocated on export which changes the parent node - during import, the parents of
            // not "officially" relocated nodes is checked and an assertion is thrown
            Assert.AreEqual(0, m_database.RootGroup.GetEntries(true).Count(e => e.GetTitle() == "Changed"));
        }

       

        [Test]
        public void ShouldNotImportDatabasesWithDifferentUsers()
        {
            var exportPath = GetTestPath();
            m_syncManager.AddExportPath(exportPath);

            var userMrX = TestHelper.GetUserRootNodeByNameFor(m_database, "mrX");
            var userMrY = TestHelper.GetUserRootNodeByNameFor(m_database, "mrY");
            m_database.GetExportGroup().Groups.GetAt(0).AddEntry(PwNode.CreateProxyNode(userMrY), true);

            var existingEntry = new PwEntry(true, true);
            existingEntry.SetTitle("Entry Version 1");
            m_database.RootGroup.AddEntry(existingEntry, true);
            m_database.RootGroup.AddEntry(PwNode.CreateProxyNode(userMrY), true);

            m_treeManager.CorrectStructure();

            string exportFile = exportPath + SyncSource.FileNameFor(userMrY) + SyncExporter.FileExtension;
            Assert.IsFalse(File.Exists(exportFile));

            m_syncManager.Export();

            existingEntry.SetTitle("Entry Version 2");

            var deltaDBInitial = new PwDatabase();
            deltaDBInitial.Open(IOConnectionInfo.FromPath(exportFile), m_standardKey, null);
            Assert.AreEqual(0, deltaDBInitial.RootGroup.GetEntries(true).Count(e => e.GetTitle() == "Entry Version 2"));
            Assert.AreEqual(1, deltaDBInitial.RootGroup.GetEntries(true).Count(e => e.GetTitle() == "Entry Version 1"));
            deltaDBInitial.Close();

            m_syncManager.AddImportPath(exportFile);
            m_database.GetImportGroup().Groups.GetAt(0).Entries.GetAt(0).SetPassword("InvalidPassword");

            m_syncManager.RefeshSourcesList();

            Assert.AreEqual(1, m_database.RootGroup.GetEntries(true).Count(e => e.GetTitle() == "Entry Version 2"));
            Assert.AreEqual(0, m_database.RootGroup.GetEntries(true).Count(e => e.GetTitle() == "Entry Version 1"));
        }
    }
}
