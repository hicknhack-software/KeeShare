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
using KeePassLib.Collections;
using KeeShare;
using KeePassLib.Security;
using System;
using System.Linq;
using System.Collections.Generic;

namespace KeeShareTest {
  [TestFixture]
  public class TreeManagerUnitTest {
    //MISSING TESTS FOR GROUP AGGREGATION

    private PwDatabase m_database;
    private TreeManagerAccessor m_treeManager;
    //private int m_sleepHackTime = 5; // NOTE CK: I have no idea why we need to sleep, but 5ms waiting should be fine enough

    [SetUp]
    public void TestInit() {
      //standard for all tests is an empty database with only the copyRootGroup in it (no PwEntries)
      m_database = TestHelper.CreateDatabase("recycler");
      m_treeManager = new TreeManagerAccessor();
    }

    [TearDown]
    public void TestCleanup() {
      m_database = null;
      m_treeManager = null;
    }

    [Test]
    public void ShouldCreateUserManagermentGroups() {
      m_treeManager.Initialize(m_database);
      var usersGroup = TestHelper.GetUsersGroupFor(m_database);
      var groupsGroup = TestHelper.GetGroupsGroupFor(m_database);
      Assert.IsNotNull(usersGroup);
      Assert.AreEqual(KeeShare.KeeShare.UsersGroupName, usersGroup.Name);
      Assert.IsNotNull(groupsGroup);
      Assert.AreEqual(KeeShare.KeeShare.GroupsGroupName, groupsGroup.Name);
    }

    [Test]
    public void NewUserShouldCreateValidTreeStructure() {
      m_treeManager.Initialize(m_database);
      m_treeManager.CreateNewUser("Hans");

      PwGroup usersGroup = TestHelper.GetUsersGroupFor(m_database);
      Assert.AreEqual(1, usersGroup.Entries.UCount);
      Assert.AreEqual(1, usersGroup.Groups.UCount);

      PwGroup userHome = TestHelper.GetUserHomeNodeFor(m_database, 0);
      Assert.AreEqual(1, userHome.Entries.UCount);
      Assert.AreEqual("Hans", userHome.Name);

      PwEntry userEntry = TestHelper.GetUserRootNodeFor(m_database, 0);
      Assert.AreEqual("Hans", userEntry.Strings.ReadSafe(KeeShare.KeeShare.TitleField));
      Assert.IsFalse(userEntry.IsProxyNode());
      Assert.IsFalse(userEntry.IsNormalPwEntry());

      PwEntry userProxy = TestHelper.GetUserRootProxyFor(m_database, 0);
      Assert.AreEqual("Hans", userProxy.Strings.ReadSafe(KeeShare.KeeShare.TitleField));
      Assert.IsTrue(userProxy.IsProxyNode());

      Assert.AreEqual(2, NumberOfEntriesIn(m_database)); // a root node and a proxy node

      IsUsersGroupSane(m_database, 1);
    }

    [Test]
    public void ShouldNotCreateInvalidUsers() {
      m_treeManager.Initialize(m_database);
      Assert.Throws<ArgumentException>(delegate { m_treeManager.CreateNewUser(null); });

      PwGroup usersGroup = TestHelper.GetUsersGroupFor(m_database);
      Assert.AreEqual(0, usersGroup.Groups.UCount);
    }

    [Test]
    public void ShouldAllowUsersWithSameName() {
      m_treeManager.Initialize(m_database);
      m_treeManager.CreateNewUser("Hans");
      m_treeManager.CreateNewUser("Hans");

      PwGroup usersGroup = TestHelper.GetUsersGroupFor(m_database);
      Assert.AreEqual(2, usersGroup.Entries.UCount);
      Assert.AreEqual(2, usersGroup.Groups.UCount);

      PwGroup userGroup1 = TestHelper.GetUserHomeNodeFor(m_database, 0);
      Assert.AreEqual(1, userGroup1.Entries.UCount);
      Assert.AreEqual("Hans", userGroup1.Name);
      PwGroup userGroup2 = TestHelper.GetUserHomeNodeFor(m_database, 1);
      Assert.AreEqual(1, userGroup2.Entries.UCount);
      Assert.AreEqual("Hans", userGroup2.Name);
      Assert.AreNotSame(userGroup1, userGroup2);

      PwEntry userEntry1 = TestHelper.GetUserRootNodeFor(m_database, 0);
      Assert.AreEqual("Hans", userEntry1.Strings.ReadSafe(KeeShare.KeeShare.TitleField));
      Assert.IsFalse(userEntry1.IsProxyNode());
      Assert.IsFalse(userEntry1.IsNormalPwEntry());
      PwEntry userEntry2 = TestHelper.GetUserRootNodeFor(m_database, 1);
      Assert.AreEqual("Hans", userEntry2.Strings.ReadSafe(KeeShare.KeeShare.TitleField));
      Assert.IsFalse(userEntry2.IsProxyNode());
      Assert.IsFalse(userEntry2.IsNormalPwEntry());
      Assert.AreNotSame(userEntry1, userEntry2);
      Assert.AreNotEqual(userEntry1.Uuid, userEntry2.Uuid);

      PwEntry userProxy1 = TestHelper.GetUserRootProxyFor(m_database, 0);
      Assert.IsTrue(userProxy1.IsProxyNode());
      PwEntry userProxy2 = TestHelper.GetUserRootProxyFor(m_database, 1);
      Assert.IsTrue(userProxy2.IsProxyNode());
      Assert.AreNotSame(userProxy1, userProxy2);
      Assert.AreNotEqual(userProxy1.Strings.ReadSafe(KeeShare.KeeShare.UuidLinkField), userProxy2.Strings.ReadSafe(KeeShare.KeeShare.UuidLinkField));

      Assert.AreEqual(4, NumberOfEntriesIn(m_database)); // each a root node and a proxy node!

      IsUsersGroupSane(m_database, 2);

    }

    [Test]
    public void CreateProxyNodeForStandardPwEntry() {
      m_treeManager.Initialize(m_database);
      PwEntry pwd = new PwEntry(true, true);
      pwd.Strings.Set(KeeShare.KeeShare.TitleField, new ProtectedString(false, "testTitle"));
      pwd.Strings.Set(KeeShare.KeeShare.PasswordField, new ProtectedString(false, "testPwd"));
      PwEntry proxy = pwd.CreateProxyNode();

      Assert.AreEqual("testTitle", proxy.Strings.ReadSafe(KeeShare.KeeShare.TitleField));
      Assert.AreEqual("testPwd", proxy.Strings.ReadSafe(KeeShare.KeeShare.PasswordField));
      Assert.AreEqual(pwd.Uuid.ToHexString(), proxy.Strings.ReadSafe(KeeShare.KeeShare.UuidLinkField));
    }

    [Test]
    public void CreateProxyFromAnotherUserProxyNode() {
      m_treeManager.Initialize(m_database);
      m_treeManager.CreateNewUser("mrX");

      PwEntry mrX = TestHelper.GetUserRootNodeFor(m_database, 0);
      PwEntry userProxy = mrX.CreateProxyNode();
      Assert.AreEqual("mrX", userProxy.Strings.ReadSafe(KeeShare.KeeShare.TitleField));
      Assert.AreEqual(mrX.Uuid.ToHexString(), userProxy.Strings.ReadSafe(KeeShare.KeeShare.UuidLinkField));
      Assert.AreNotEqual(mrX.Uuid.ToHexString(), userProxy.Uuid.ToHexString());
    }

    [Test]
    public void CreateProxyFromAnotherUserRootNode() {
      m_treeManager.Initialize(m_database);
      m_treeManager.CreateNewUser("mrX");

      PwEntry rootProxy = TestHelper.GetUserRootProxyFor(m_database, 0);
      PwEntry userProxy = rootProxy.CreateProxyNode();
      Assert.AreEqual("mrX", userProxy.Strings.ReadSafe(KeeShare.KeeShare.TitleField));
      Assert.AreEqual(rootProxy.Strings.ReadSafe(KeeShare.KeeShare.UuidLinkField), userProxy.Strings.ReadSafe(KeeShare.KeeShare.UuidLinkField));
      Assert.AreNotEqual(rootProxy.Uuid.ToHexString(), userProxy.Uuid.ToHexString());
    }


    [Test]
    public void DeleteLastUserShouldCleanTreeStructure() {
      m_treeManager.Initialize(m_database);
      m_treeManager.CreateNewUser("mrX");

      PwEntry mrX = TestHelper.GetUserRootNodeFor(m_database, 0);
      m_treeManager.DeleteUser(mrX);

      Assert.AreEqual(0, NumberOfEntriesIn(m_database));
    }

    [Test]
    public void DeleteOneUserShouldCleanTreeStructureOnlyFromThisUser() {
      m_treeManager.Initialize(m_database);
      m_treeManager.CreateNewUser("mrX");
      m_treeManager.CreateNewUser("mrY");

      Assert.AreEqual(4, NumberOfEntriesIn(m_database));
      PwEntry mrX = TestHelper.GetUserRootNodeFor(m_database, 0);
      m_treeManager.DeleteUser(mrX);

      Assert.AreEqual(2, NumberOfEntriesIn(m_database));
    }

    [Test]  //test complete
    public void DeleteOneUserShouldRemoveObsoleteProxyNodes() {
      m_treeManager.Initialize(m_database);
      m_treeManager.CreateNewUser("mrX");
      m_treeManager.CreateNewUser("mrY");

      //a DeleteUser should also delete all proxies of this user!
      //so we create some and look if all proxies will be deleted...
      PwGroup testGroup1 = new PwGroup(true, false);
      PwGroup testGroup2 = new PwGroup(true, false);
      PwGroup testGroup3 = new PwGroup(true, false);

      m_database.RootGroup.AddGroup(testGroup1, true);
      m_database.RootGroup.AddGroup(testGroup2, true);

      testGroup2.AddGroup(testGroup3, true);

      PwEntry mrX = TestHelper.GetUserRootNodeByNameFor(m_database, "mrX");
      PwEntry mrY = TestHelper.GetUserRootNodeByNameFor(m_database, "mrY");

      PwEntry mrXproxy1 = mrX.CreateProxyNode();
      PwEntry mrXproxy2 = mrX.CreateProxyNode();
      PwEntry mrXproxy3 = mrX.CreateProxyNode();

      testGroup1.AddEntry(mrXproxy1, true);
      testGroup2.AddEntry(mrXproxy2, true);
      testGroup3.AddEntry(mrXproxy3, true);

      Assert.AreEqual(7, NumberOfEntriesIn(m_database)); // 2 standard proxies each + 3 additional proxies for mrX

      m_treeManager.DeleteUser(mrX);

      Assert.AreEqual(2, NumberOfEntriesIn(m_database));
      foreach (PwEntry proxy in m_database.RootGroup.GetEntries(true)) {
        Assert.AreEqual("mrY", proxy.Strings.ReadSafe(KeeShare.KeeShare.TitleField));
      }
      IsUsersGroupSane(m_database, 1);
    }

    [Test]
    public void GetAllUserRootNodesReturnsOnlyValidRootNodes() {
      m_treeManager.Initialize(m_database);
      PwEntry root1 = new PwEntry(true, true);
      PwEntry root2 = new PwEntry(true, true);
      PwEntry root3 = new PwEntry(true, true);

      PwEntry normalEntry1 = new PwEntry(true, true);
      PwEntry normalEntry2 = new PwEntry(true, true);
      PwGroup level1 = new PwGroup();

      //initial data
      root1.Strings.Set(KeeShare.KeeShare.UuidLinkField, new ProtectedString(false, root1.Uuid.ToHexString()));
      root2.Strings.Set(KeeShare.KeeShare.UuidLinkField, new ProtectedString(false, root2.Uuid.ToHexString()));
      root3.Strings.Set(KeeShare.KeeShare.UuidLinkField, new ProtectedString(false, root3.Uuid.ToHexString()));

      m_database.RootGroup.AddEntry(root1, true);
      m_database.RootGroup.AddEntry(root2, true);
      m_database.RootGroup.AddEntry(normalEntry1, true);
      m_database.RootGroup.AddGroup(level1, true);
      level1.AddEntry(normalEntry2, true);
      level1.AddEntry(root3, true);

      PwObjectList<PwEntry> rootNodes = m_database.GetAllUserNodes();
      Assert.AreEqual(3, rootNodes.UCount);

      Assert.AreEqual(root1, rootNodes.GetAt(0));
      Assert.AreEqual(root2, rootNodes.GetAt(1));
      Assert.AreEqual(root3, rootNodes.GetAt(2));
    }

    [Flags]
    enum Check {
      Invalid,
      Proxy,
      Home,
      Root
    };

    [Test]
    public void CreatesAHomeGroupWithARootEntryAndAProxyNodeForEachUser() {
      m_treeManager.Initialize(m_database);
      Dictionary<string, Check> users = new Dictionary<string, Check>() {
                { "Hans", Check.Invalid },
                { "Klaus", Check.Invalid },
                { "mrX", Check.Invalid }
            };
      foreach (string user in users.Keys) {
        m_treeManager.CreateNewUser(user);
      }
      var entries = m_database.RootGroup.GetEntries(true);
      var usersGroup = TestHelper.GetUsersGroupFor(m_database);
      Assert.AreEqual(users.Count * 2, entries.UCount);
      foreach (PwEntry entry in entries) {
        if (entry.IsProxyNode()) {
          users[entry.Strings.ReadSafe(KeeShare.KeeShare.TitleField)] |= Check.Proxy;
        }
        else if (entry.IsUserRootNode()) {
          string title = entry.Strings.ReadSafe(KeeShare.KeeShare.TitleField);
          users[title] |= Check.Root;
          if (entry.ParentGroup.Name == title && entry.ParentGroup.ParentGroup == usersGroup) {
            users[title] |= Check.Home;
          }
        }
      }
      foreach (string user in users.Keys) {
        Assert.AreEqual(Check.Home | Check.Root | Check.Proxy, users[user]);
      }
    }

    [Test]
    public void MoveRootUserToAnotherFolderShouldCreateAProxyInTheTarget() {
      m_treeManager.Initialize(m_database);
      m_treeManager.CreateNewUser("Hans");
      m_treeManager.CreateNewUser("klaus");
      m_treeManager.CreateNewUser("mrX");

      PwEntry hans = TestHelper.GetUserRootNodeByNameFor(m_database, "Hans");
      PwEntry klaus = TestHelper.GetUserRootNodeByNameFor(m_database, "klaus");
      PwEntry mrx = TestHelper.GetUserRootNodeByNameFor(m_database, "mrX");
      Assert.IsNotNull(hans);
      Assert.IsNotNull(klaus);
      Assert.IsNotNull(mrx);

      // Simulate move by the user ->  RootNode changes location to destination folder
      Assert.IsTrue(mrx.ParentGroup.Entries.Remove(mrx));
      m_database.RootGroup.AddEntry(mrx, true);

      // Correction should move the RootNode back and create a ProxyNode instead
      m_treeManager.CorrectStructure();

      Assert.AreEqual(7, NumberOfEntriesIn(m_database)); // a root and a proxy node for each user + a new proxy 
      IsUsersGroupSane(m_database, 3);
    }

    [Test]
    public void PreventMoveOfRootUserToOtherUsersHome() {
      m_treeManager.Initialize(m_database);
      m_treeManager.CreateNewUser("Hans");
      m_treeManager.CreateNewUser("klaus");
      m_treeManager.CreateNewUser("mrX");

      PwEntry hans = TestHelper.GetUserRootNodeByNameFor(m_database, "Hans");
      PwEntry klaus = TestHelper.GetUserRootNodeByNameFor(m_database, "klaus");
      PwEntry mrx = TestHelper.GetUserRootNodeByNameFor(m_database, "mrX");
      Assert.IsNotNull(hans);
      Assert.IsNotNull(klaus);
      Assert.IsNotNull(mrx);

      // Simulate move by the user ->  RootNode changes location to destination folder
      //move to foreign home => only have to move back home! nothing else!
      klaus.ParentGroup.Entries.Remove(klaus);
      hans.ParentGroup.AddEntry(klaus, true);

      // Correction should move the RootNode back without creating a proxy
      m_treeManager.CorrectStructure();

      Assert.AreEqual(6, NumberOfEntriesIn(m_database)); // a root and a proxy node for each user - no new node
      IsUsersGroupSane(m_database, 3);
    }

    [Test]
    public void MovingARootNodeToGarbageShouldRemoveTheUserAndItsProxies() {
      m_treeManager.Initialize(m_database);
      m_treeManager.CreateNewUser("Hans");
      m_treeManager.CreateNewUser("klaus");
      m_treeManager.CreateNewUser("mrX");
      m_treeManager.CorrectStructure();

      PwEntry hans = TestHelper.GetUserRootNodeByNameFor(m_database, "Hans");
      PwEntry klaus = TestHelper.GetUserRootNodeByNameFor(m_database, "klaus");
      PwEntry mrx = TestHelper.GetUserRootNodeByNameFor(m_database, "mrX");
      Assert.IsNotNull(hans);
      Assert.IsNotNull(klaus);
      Assert.IsNotNull(mrx);

      // Create a proxy to delete            
      Assert.IsTrue(hans.ParentGroup.Entries.Remove(hans));
      m_database.RootGroup.AddEntry(hans, true);

      Assert.IsTrue(klaus.ParentGroup.Entries.Remove(klaus));
      m_database.RootGroup.AddEntry(klaus, true);

      m_treeManager.CorrectStructure();
      Assert.AreEqual(8, NumberOfEntriesIn(m_database)); // each user a root node and a proxy + 2 new proxies

      // Move RootNode to garbage
      hans.ParentGroup.Entries.Remove(hans);
      PwGroup trash = m_database.RootGroup.FindGroup(m_database.RecycleBinUuid, false);
      trash.AddEntry(hans, true);
      Assert.AreEqual(8, NumberOfEntriesIn(m_database));

      m_treeManager.CorrectStructure();

      Assert.AreEqual(5, NumberOfEntriesIn(m_database)); // each remaining user a root node and a proxy + 1 proxy
      var userNodes = m_database.GetAllUserNodes();
      Assert.AreEqual(2, userNodes.UCount);
      Assert.IsTrue(userNodes.Any(e => "klaus" == e.Strings.ReadSafe(KeeShare.KeeShare.TitleField)));
      Assert.IsTrue(userNodes.Any(e => "mrX" == e.Strings.ReadSafe(KeeShare.KeeShare.TitleField)));

      //everytime the UsersGroups should be sane!
      IsUsersGroupSane(m_database, 2);
    }

    [Test]
    public void RenameOfUserRootShouldRenameItsHomeAndAllProxies() {
      m_treeManager.Initialize(m_database);
      m_treeManager.CreateNewUser("mrX");
      PwEntry userRootNode = TestHelper.GetUserRootNodeFor(m_database, 0);
      PwEntry userHomeProxyNode = TestHelper.GetUserRootProxyFor(m_database, 0);
      PwEntry userExternProxyNode = userRootNode.CreateProxyNode();
      PwGroup userHome = TestHelper.GetUserHomeNodeFor(m_database, 0);
      m_database.RootGroup.AddEntry(userExternProxyNode, true);
      userRootNode.CreateBackup(m_database);

      userRootNode.Strings.Set(KeeShare.KeeShare.TitleField, new ProtectedString(false, "mrNew"));
      TestHelper.SimulateTouch(userRootNode);

      m_treeManager.CorrectStructure();
      //refresh all references after update
      userRootNode = TestHelper.GetUserRootNodeFor(m_database, 0);
      userHomeProxyNode = TestHelper.GetUserRootNodeFor(m_database, 0);
      userExternProxyNode = m_database.RootGroup.Entries.GetAt(0);
      userHome = TestHelper.GetUserHomeNodeFor(m_database, 0);

      //after that update all proxyNodes schould have become the same name as the rootNode_X
      Assert.AreEqual("mrNew", userHomeProxyNode.Strings.ReadSafe(KeeShare.KeeShare.TitleField));
      Assert.AreEqual("mrNew", userExternProxyNode.Strings.ReadSafe(KeeShare.KeeShare.TitleField));
      //even the home of the user should have the new name
      Assert.AreEqual("mrNew", userHome.Name);
      //everytime the UsersGroups should be sane!
      IsUsersGroupSane(m_database, 1);
    }

    [Test]
    public void RenameOfUserHomeProxyShouldRenameItsRootAndHomeAndAllProxies() {
      m_treeManager.Initialize(m_database);
      m_treeManager.CreateNewUser("mrX");
      PwEntry userRootNode = TestHelper.GetUserRootNodeFor(m_database, 0);
      PwEntry userHomeProxyNode = TestHelper.GetUserRootProxyFor(m_database, 0);
      PwEntry userExternProxyNode = userRootNode.CreateProxyNode();
      PwGroup userHome = TestHelper.GetUserHomeNodeFor(m_database, 0);
      m_database.RootGroup.AddEntry(userExternProxyNode, true);

      //rename a proxyNode
      userHomeProxyNode.Strings.Set(KeeShare.KeeShare.TitleField, new ProtectedString(false, "nowMrA"));
      TestHelper.SimulateTouch(userHomeProxyNode);

      m_treeManager.CorrectStructure();
      //refresh all references after update
      userRootNode = TestHelper.GetUserRootNodeFor(m_database, 0);
      userHomeProxyNode = TestHelper.GetUserRootNodeFor(m_database, 0);
      userExternProxyNode = m_database.RootGroup.Entries.GetAt(0);
      userHome = TestHelper.GetUserHomeNodeFor(m_database, 0);
      //after that update same tests here
      Assert.AreEqual("nowMrA", userRootNode.Strings.ReadSafe(KeeShare.KeeShare.TitleField));
      Assert.AreEqual("nowMrA", userExternProxyNode.Strings.ReadSafe(KeeShare.KeeShare.TitleField));
      Assert.AreEqual("nowMrA", userHome.Name);
      //everytime the UsersGroups should be sane!
      IsUsersGroupSane(m_database, 1);
    }

    [Test]
    public void RenameOfUserHomeShouldRenameItsRootAndAllProxies() {
      m_treeManager.Initialize(m_database);
      m_treeManager.CreateNewUser("mrX");
      PwEntry userRootNode = TestHelper.GetUserRootNodeFor(m_database, 0);
      PwEntry userHomeProxyNode = TestHelper.GetUserRootProxyFor(m_database, 0);
      PwEntry userExternProxyNode = userRootNode.CreateProxyNode();
      PwGroup userHome = TestHelper.GetUserHomeNodeFor(m_database, 0);
      m_database.RootGroup.AddEntry(userExternProxyNode, true);

      //rename the homeFolder
      userHome.Name = "FolderNameChanged";
      TestHelper.SimulateTouch(userHome);

      m_treeManager.CorrectStructure();
      //refresh all references after update
      userRootNode = TestHelper.GetUserRootNodeFor(m_database, 0);
      userHomeProxyNode = TestHelper.GetUserRootNodeFor(m_database, 0);
      userExternProxyNode = m_database.RootGroup.Entries.GetAt(0);
      userHome = TestHelper.GetUserHomeNodeFor(m_database, 0);
      //after that update same tests here
      Assert.AreEqual("FolderNameChanged", userRootNode.Strings.ReadSafe(KeeShare.KeeShare.TitleField));
      Assert.AreEqual("FolderNameChanged", userHomeProxyNode.Strings.ReadSafe(KeeShare.KeeShare.TitleField));
      Assert.AreEqual("FolderNameChanged", userExternProxyNode.Strings.ReadSafe(KeeShare.KeeShare.TitleField));

      //everytime the UsersGroups should be sane!
      IsUsersGroupSane(m_database, 1);
    }

    [Test]
    public void ShouldRemoveRedundantProxies() {
      m_treeManager.Initialize(m_database);
      m_treeManager.CreateNewUser("mrX");

      PwEntry mrX = TestHelper.GetUserRootNodeFor(m_database, 0);
      PwEntry proxy1 = mrX.CreateProxyNode();
      PwEntry proxy2 = mrX.CreateProxyNode();
      m_database.RootGroup.AddEntry(proxy1, true);
      m_database.RootGroup.AddEntry(proxy2, true);

      Assert.AreEqual(4, NumberOfEntriesIn(m_database));
      Assert.AreEqual(2, m_database.RootGroup.Entries.UCount);

      m_treeManager.CorrectStructure();

      Assert.AreEqual(3, NumberOfEntriesIn(m_database));
      Assert.AreEqual(1, m_database.RootGroup.Entries.UCount);
    }

    [Test]
    public void RespectProxiesOfDifferentUsersWithSameNameButDeleteRedudantOnes() {
      m_treeManager.Initialize(m_database);
      m_treeManager.CreateNewUser("mrX");
      m_treeManager.CreateNewUser("mrX");

      PwEntry mrX1 = TestHelper.GetUserRootNodeFor(m_database, 0);
      PwEntry mrX2 = TestHelper.GetUserRootNodeFor(m_database, 1);
      Assert.IsTrue(mrX1.IsUserRootNode());
      Assert.IsTrue(mrX2.IsUserRootNode());
      PwEntry proxyX1_1 = mrX1.CreateProxyNode();
      PwEntry proxyX1_2 = mrX1.CreateProxyNode();
      PwEntry proxyX2_1 = mrX2.CreateProxyNode();
      PwEntry proxyX2_2 = mrX2.CreateProxyNode();
      m_database.RootGroup.AddEntry(proxyX1_1, true);
      m_database.RootGroup.AddEntry(proxyX1_2, true);
      m_database.RootGroup.AddEntry(proxyX2_1, true);
      m_database.RootGroup.AddEntry(proxyX2_2, true);
      m_treeManager.CorrectStructure();

      Assert.AreEqual(6, NumberOfEntriesIn(m_database));
    }

    [Test]
    public void RespectProxiesOfDifferentUsersWithSameName() {
      m_treeManager.Initialize(m_database);
      m_treeManager.CreateNewUser("mrX");
      m_treeManager.CreateNewUser("mrX");
      PwEntry mrX1 = TestHelper.GetUserRootNodeFor(m_database, 0);
      PwEntry mrX2 = TestHelper.GetUserRootNodeFor(m_database, 1);
      Assert.IsTrue(mrX1.IsUserRootNode());
      Assert.IsTrue(mrX2.IsUserRootNode());
      PwEntry proxyX1 = mrX1.CreateProxyNode();
      PwEntry proxyX2 = mrX2.CreateProxyNode();
      m_database.RootGroup.AddEntry(proxyX1, true);
      m_database.RootGroup.AddEntry(proxyX2, true);
      m_treeManager.CorrectStructure();

      Assert.AreEqual(6, NumberOfEntriesIn(m_database));
    }

    [Test]
    public void MoveUserHomeShouldCreateAProxyInTheTarget() {
      m_treeManager.Initialize(m_database);
      m_treeManager.CreateNewUser("mrX");
      m_treeManager.CreateNewUser("mrY");
      PwGroup grp1 = new PwGroup(true, true, "testgrp", PwIcon.Archive);
      PwUuid grpId = grp1.Uuid;
      m_database.RootGroup.AddGroup(grp1, true);

      Assert.AreEqual(4, m_database.RootGroup.Groups.UCount);

      //move home to a normal PwGroup
      PwGroup homeX = TestHelper.GetUserHomeNodeByNameFor(m_database, "mrX");
      PwUuid homeXid = homeX.Uuid;
      homeX.ParentGroup.Groups.Remove(homeX);
      grp1.AddGroup(homeX, true);
      m_treeManager.CorrectStructure();

      grp1 = TestHelper.GetGroupByUuidFor(m_database, grpId);
      homeX = TestHelper.GetGroupByUuidFor(m_database, homeXid);
      Assert.AreEqual(TestHelper.GetUsersGroupFor(m_database), homeX.ParentGroup);
      //a new proxy has to be set where we have moved he home before
      Assert.AreEqual(0, grp1.Groups.UCount);
      Assert.AreEqual(1, grp1.Entries.UCount);
      Assert.IsTrue(grp1.Entries.GetAt(0).IsProxyNode());
      string proxyLink = grp1.Entries.GetAt(0).Strings.ReadSafe(KeeShare.KeeShare.UuidLinkField);
      string rootUid = homeX.Entries.GetAt(0).Uuid.ToHexString();
      Assert.AreEqual(proxyLink, rootUid);
      Assert.AreEqual(5, NumberOfEntriesIn(m_database));
    }

    [Test]
    public void MoveUserHomeToGarbageShoulRemoveAllUserProxies() {
      m_treeManager.Initialize(m_database);
      m_treeManager.CreateNewUser("mrX");
      m_treeManager.CreateNewUser("mrY");
      PwGroup grp1 = new PwGroup(true, true, "testgrp", PwIcon.Archive);
      PwUuid grpId = grp1.Uuid;
      m_database.RootGroup.AddGroup(grp1, true);

      Assert.AreEqual(4, m_database.RootGroup.Groups.UCount);

      //move home to a normal PwGroup
      PwGroup homeX = TestHelper.GetUserHomeNodeByNameFor(m_database, "mrX");
      PwUuid homeXid = homeX.Uuid;
      //move home to the trash
      PwGroup trash = m_database.RootGroup.FindGroup(m_database.RecycleBinUuid, true);
      homeX.ParentGroup.Groups.Remove(homeX);
      trash.AddGroup(homeX, true);
      // TODO CK: Find out if the user should be deleted already at this place or later
      m_treeManager.CorrectStructure();

      trash = m_database.RootGroup.FindGroup(m_database.RecycleBinUuid, true);
      Assert.AreEqual(1, trash.Groups.UCount);
      homeX = m_database.RootGroup.FindGroup(homeXid, true);
      Assert.AreEqual(trash, homeX.ParentGroup);
      //empty trash..
      trash.DeleteAllObjects(m_database);
      //update should delete all references to the non existing user
      m_treeManager.CorrectStructure();

      Assert.AreEqual(2, NumberOfEntriesIn(m_database));
      Assert.NotNull(TestHelper.GetUserRootNodeByNameFor(m_database, "mrY"));
    }

    [Test]
    public void MoveUserHomeToAnotheruserShoudlBeReverted() {
      m_treeManager.Initialize(m_database);
      m_treeManager.CreateNewUser("mrY");
      m_treeManager.CreateNewUser("mrZ");
      PwGroup homeY = TestHelper.GetUserHomeNodeByNameFor(m_database, "mrY");
      PwGroup homeZ = TestHelper.GetUserHomeNodeByNameFor(m_database, "mrZ");
      PwUuid homeYid = homeY.Uuid;
      PwUuid homeZid = homeZ.Uuid;

      homeY.ParentGroup.Groups.Remove(homeY);
      homeZ.AddGroup(homeY, true);
      Assert.AreEqual(1, m_database.GetUsersGroup().Groups.UCount);
      m_treeManager.CorrectStructure();

      Assert.AreEqual(2, m_database.GetUsersGroup().Groups.UCount);
      homeY = TestHelper.GetGroupByUuidFor(m_database, homeYid);
      homeZ = TestHelper.GetGroupByUuidFor(m_database, homeZid);
      Assert.AreEqual(1, homeY.Entries.UCount);
      Assert.AreEqual(0, homeY.Groups.UCount);
      Assert.AreEqual(1, homeZ.Entries.UCount);
      Assert.AreEqual(0, homeZ.Groups.UCount);
      Assert.AreEqual(4, NumberOfEntriesIn(m_database));
    }

    [Test]
    public void RenamePwdProxyNodesTest() {
      m_treeManager.Initialize(m_database);
      PwEntry pwd1 = new PwEntry(true, true);
      pwd1.Strings.Set(KeeShare.KeeShare.TitleField, new ProtectedString(false, "pwd1"));
      m_database.RootGroup.AddEntry(pwd1, true);
      pwd1.Touch(true);

      DateTime lastTouch = pwd1.LastModificationTime;

      PwEntry pwdProxy = pwd1.CreateProxyNode();
      m_database.GetGroupsGroup().AddEntry(pwdProxy, true);

      pwdProxy.LastModificationTime = lastTouch.AddTicks(10);

      m_treeManager.CorrectStructure();

      Assert.AreEqual(2, NumberOfEntriesIn(m_database));
      string pwdId = m_database.RootGroup.Entries.GetAt(0).Uuid.ToHexString();
      pwdProxy = m_database.GetGroupsGroup().Entries.GetAt(0);
      Assert.AreEqual(pwdId, pwdProxy.Strings.ReadSafe(KeeShare.KeeShare.UuidLinkField));

      pwdProxy.Strings.Set(KeeShare.KeeShare.TitleField, new ProtectedString(false, "new Title"));
      pwdProxy.LastModificationTime = lastTouch.AddTicks(23);

      m_treeManager.CorrectStructure();
      Assert.AreEqual("new Title", m_database.RootGroup.Entries.GetAt(0).Strings.ReadSafe(KeeShare.KeeShare.TitleField));
    }

    [Test]  //test complete
    public void EnsureRecycleBinTest() {
      m_treeManager.Initialize(m_database);
      m_database.RootGroup.DeleteAllObjects(m_database);
      PwGroup trash = m_database.RootGroup.FindGroup(m_database.RecycleBinUuid, true);
      Assert.IsNull(trash);
      m_treeManager.CorrectStructure();
      //userManager.EnsureRecycleBin();
      trash = m_database.RootGroup.FindGroup(m_database.RecycleBinUuid, true);
      Assert.IsNotNull(trash);
    }

    /// <summary>
    /// counts all entries in the entire database
    /// </summary>
    public uint NumberOfEntriesIn(PwDatabase db) {
      return db.RootGroup.GetEntries(true).UCount;
    }

    //test complete
    public void IsUsersGroupSane(PwDatabase db, int expectedUsers) {
      PwGroup usersGroup = m_database.GetUsersGroup();

      //anzahl angelegter nutzer sollte mit der anzahl der homeverz und proxies überienstimmen
      Assert.AreEqual(expectedUsers, usersGroup.Entries.UCount);
      Assert.AreEqual(expectedUsers, usersGroup.Groups.UCount);

      PwObjectList<PwGroup> usersHomes = usersGroup.GetGroups(false);
      foreach (PwGroup home in usersHomes) {
        PwObjectList<PwEntry> entryList = home.GetEntries(false);
        int rootCounter = 0;
        PwEntry rootNode = null;

        foreach (PwEntry entry in entryList) {
          if (entry.IsUserRootNode()) {
            rootCounter++;
            rootNode = entry;
          }
        }
        //jedes homeverz muss genau einen rootKnoten halten
        Assert.AreEqual(1, rootCounter);
        //name des rootNodes und des homeverz müssen übereinstimmen
        string homeName = home.Name;
        Assert.IsFalse(null == rootNode);
        string userName = rootNode.Strings.ReadSafe(KeeShare.KeeShare.TitleField);
        Assert.AreEqual(homeName, userName);
      }
    }
  }
}