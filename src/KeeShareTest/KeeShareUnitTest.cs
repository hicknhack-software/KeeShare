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
using KeeShare;
using NUnit.Framework;
using System.IO;
using System.Linq;

namespace KeeShareTest
{
    [TestFixture]
    class KeeShareUnitTest
    {
        private string GetTestPath()
        {
            return Directory.GetCurrentDirectory() + @"\KeeShareTestFiles\KeeShare\";
        }

        [SetUp]
        public void TestInit()
        {
            TestHelper.CleanFilesystem(GetTestPath());
        }

        [TearDown]
        public void TestCleanup()
        {
        }


        [Test]
        public void InitializeTest()
        {
            var keeShare = new KeeShare.KeeShare();
            var database = TestHelper.CreateDatabase();
            keeShare.Initialize(database);

            Assert.IsTrue(keeShare.IsInitialized());
        }

        [Test]
        public void ShouldHandleExportAndImportOfDifferentDatabasesSuccessfully()
        {
            var exportKeeShare = new KeeShare.KeeShare();
            var exportDatabase = TestHelper.CreateDatabase();
            exportKeeShare.Initialize(exportDatabase);

            var treeManagerAccessor = new TreeManagerAccessor();
            treeManagerAccessor.Initialize(exportDatabase);
            treeManagerAccessor.CreateNewUser("MrX");
            exportKeeShare.EnsureValidTree(exportDatabase);

            var userNode = TestHelper.GetUserRootNodeByNameFor(exportDatabase, "MrX");
            var userHome = TestHelper.GetUserHomeNodeByNameFor(exportDatabase, "MrX");
            var exportRootEntry = new PwEntry(true, true);
            exportRootEntry.SetTitle("ExportRootEntry");
            exportDatabase.RootGroup.AddEntry(exportRootEntry, true);
            
            var exportPath = GetTestPath();
            var exportFile = exportPath + SyncSource.FileNameFor(userNode) + SyncExporter.FileExtension;
            exportKeeShare.AddExportPath(exportPath);
            var exportTarget = exportDatabase.GetExportGroup().Groups.GetAt(0);
            exportTarget.AddEntry(userNode.CreateProxyNode(), true);

            var exportHomeEntry = new PwEntry(true, true);
            exportHomeEntry.SetTitle("ExportHomeEntry");
            userHome.AddEntry(exportHomeEntry, true);
            exportDatabase.RootGroup.AddEntry(userNode.CreateProxyNode(), true);

            var importDatabase = TestHelper.CreateDatabase();
            var importKeeShare = new KeeShare.KeeShare();
            importKeeShare.Initialize(importDatabase);

            exportKeeShare.Export();

            importKeeShare.AddImportPath(exportFile);
            var importGroup = importDatabase.GetImportGroup().Groups.GetAt(0);
            var importSource = importGroup.Entries.GetAt(0);
            importSource.SetPassword(userNode.Strings.ReadSafe(KeeShare.KeeShare.PasswordField));

            importKeeShare.EnsureValidTree(importDatabase);
        
            Assert.AreEqual(1, importDatabase.RootGroup.GetEntries(true).CloneShallowToList().Count(e => e.GetTitle() == "ExportRootEntry"));
            Assert.AreEqual(1, importDatabase.RootGroup.GetEntries(true).CloneShallowToList().Count(e => e.GetTitle() == "ExportHomeEntry"));
        }
    }
}
