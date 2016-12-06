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
using KeePassLib.Security;
using NUnit.Core;

namespace KeeShareTest
{
	[TestFixture]
	class ExtensionMethodsTest
	{
		PwDatabase database;
		TreeManager userManager;
		PwGroup rootGroup;
		PwEntry root1 = new PwEntry( true, false );
		PwEntry root2 = new PwEntry( true, false );
		//normal entries
		PwEntry normalEntry1;
		PwEntry normalEntry2;
		PwEntry normalEntry3;
		PwEntry pwdProxyTo1;
		PwEntry pwdProxyTo3;
		PwEntry pwdProxyTo3_1;
		PwEntry brokenProxy1;
		PwEntry proxyToRoot1;
		PwEntry brokenProxy2;


		[SetUp]
		public void TestInit()
		{
			database = new PwDatabase();
			database.RootGroup = new PwGroup();
			userManager = new TreeManager();
			userManager.Initialize( database );

			rootGroup = database.RootGroup;

			normalEntry1 = new PwEntry( true, false );
			normalEntry2 = new PwEntry( true, false );
			normalEntry3 = new PwEntry( true, false );
			pwdProxyTo1 = new PwEntry( true, false );
			pwdProxyTo3 = new PwEntry( true, false );
			pwdProxyTo3_1 = new PwEntry( true, false );
			proxyToRoot1 = new PwEntry( true, false );
			brokenProxy1 = new PwEntry( true, false );
			brokenProxy2 = new PwEntry( true, false );

			//initial data
			root1.Strings.Set(KeeShare.KeeShare.UuidLinkField, new ProtectedString( false, root1.Uuid.ToHexString() ) );
			root2.Strings.Set(KeeShare.KeeShare.UuidLinkField, new ProtectedString( false, root2.Uuid.ToHexString() ) );

			//pwdProxies
			pwdProxyTo1.Strings.Set(KeeShare.KeeShare.UuidLinkField, new ProtectedString( false, normalEntry1.Uuid.ToHexString() ) );
			pwdProxyTo3.Strings.Set(KeeShare.KeeShare.UuidLinkField, new ProtectedString( false, normalEntry3.Uuid.ToHexString() ) );
			pwdProxyTo3_1.Strings.Set(KeeShare.KeeShare.UuidLinkField, new ProtectedString( false, normalEntry3.Uuid.ToHexString() ) );
			//proxyNode => references rootNode1
			proxyToRoot1.Strings.Set(KeeShare.KeeShare.UuidLinkField, new ProtectedString( false, root1.Uuid.ToHexString() ) );

			//entry with empty stringfield
			brokenProxy1.Strings.Set(KeeShare.KeeShare.UuidLinkField, new ProtectedString( false, "" ) );
			//entry with junk stringfield
			brokenProxy2.Strings.Set(KeeShare.KeeShare.UuidLinkField, new ProtectedString( false, "falseLinkToNonhere" ) );


			rootGroup.AddEntry( root1, true );
			rootGroup.AddEntry( root2, true );
			rootGroup.AddEntry( normalEntry1, true );
			rootGroup.AddEntry( normalEntry2, true );
			rootGroup.AddEntry( normalEntry3, true );
			rootGroup.AddEntry( pwdProxyTo1, true );
			rootGroup.AddEntry( pwdProxyTo3, true );
			rootGroup.AddEntry( pwdProxyTo3_1, true );
			rootGroup.AddEntry( brokenProxy1, true );
			rootGroup.AddEntry( proxyToRoot1, true );
			rootGroup.AddEntry( brokenProxy2, true );

		}

		[TearDown]
		public void TestCleanup()
		{
			database = null;
			userManager = null;
		}

		[Test]
		public void IsProxyNodeTest()
		{
			//should all be false:
			Assert.IsFalse( root1.IsProxyNode() );
			Assert.IsFalse( root2.IsProxyNode() );
			Assert.IsFalse( normalEntry1.IsProxyNode() );
			Assert.IsFalse( normalEntry2.IsProxyNode() );
			Assert.IsFalse( normalEntry3.IsProxyNode() );

			//should all be true:
			Assert.IsTrue( pwdProxyTo1.IsProxyNode() );
			Assert.IsTrue( pwdProxyTo3.IsProxyNode() );
			Assert.IsTrue( pwdProxyTo3_1.IsProxyNode() );
			Assert.IsTrue( proxyToRoot1.IsProxyNode() );
			Assert.IsTrue( brokenProxy1.IsProxyNode() );
			Assert.IsTrue( brokenProxy2.IsProxyNode() );
		}

		[Test]
		public void IsUserRootNodeTest()
		{
			//should all be false:
			Assert.IsFalse( normalEntry1.IsUserRootNode() );
			Assert.IsFalse( normalEntry2.IsUserRootNode() );
			Assert.IsFalse( normalEntry3.IsUserRootNode() );
			Assert.IsFalse( pwdProxyTo1.IsUserRootNode() );
			Assert.IsFalse( pwdProxyTo3.IsUserRootNode() );
			Assert.IsFalse( pwdProxyTo3_1.IsUserRootNode() );
			Assert.IsFalse( proxyToRoot1.IsUserRootNode() );
			Assert.IsFalse( brokenProxy1.IsUserRootNode() );
			Assert.IsFalse( brokenProxy2.IsUserRootNode() );

			//should all be true:
			Assert.IsTrue( root1.IsUserRootNode() );
			Assert.IsTrue( root2.IsUserRootNode() );
		}

		[Test]
		public void IsNormalPwEntryTest()
		{
			//should all be false:
			Assert.IsFalse( root1.IsNormalPwEntry() );
			Assert.IsFalse( root2.IsNormalPwEntry() );
			Assert.IsFalse( pwdProxyTo1.IsNormalPwEntry() );
			Assert.IsFalse( pwdProxyTo3.IsNormalPwEntry() );
			Assert.IsFalse( pwdProxyTo3_1.IsNormalPwEntry() );
			Assert.IsFalse( proxyToRoot1.IsNormalPwEntry() );
			Assert.IsFalse( brokenProxy1.IsNormalPwEntry() );
			Assert.IsFalse( brokenProxy2.IsNormalPwEntry() );

			//should all be true:
			Assert.IsTrue( normalEntry1.IsNormalPwEntry() );
			Assert.IsTrue( normalEntry2.IsNormalPwEntry() );
			Assert.IsTrue( normalEntry3.IsNormalPwEntry() );
		}

		[Test]
		public void IsParentTest()
		{
			PwDatabase db = new PwDatabase();
			db.RootGroup = new PwGroup();
			TreeManager um = new TreeManager();
			userManager.Initialize( db );
			rootGroup = db.RootGroup;

			//groups are named like g<# of group>_<level in tree> level 0 is the copyRootGroup
			PwGroup g1_1 = new PwGroup( true, true, "g1_1", PwIcon.Apple );
			PwGroup g2_1 = new PwGroup( true, true, "g2_1", PwIcon.Apple );
			PwGroup g3_2 = new PwGroup( true, true, "g3_2", PwIcon.Apple );
			PwGroup g4_3 = new PwGroup( true, true, "g4_3", PwIcon.Apple );

			rootGroup.AddGroup( g1_1, true );
			rootGroup.AddGroup( g2_1, true );
			g2_1.AddGroup( g3_2, true );
			g3_2.AddGroup( g4_3, true );

			PwEntry pe1_0 = new PwEntry( true, true );
			PwEntry pe2_1 = new PwEntry( true, true );
			PwEntry pe3_2 = new PwEntry( true, true );
			PwEntry pe4_3 = new PwEntry( true, true );

			rootGroup.AddEntry( pe1_0, true );
			g2_1.AddEntry( pe2_1, true );
			g3_2.AddEntry( pe3_2, true );
			g4_3.AddEntry( pe4_3, true );

            Assert.IsTrue( pe1_0.IsInsideParent( rootGroup ) );
			Assert.IsTrue( pe4_3.IsInsideParent( rootGroup ) );
			Assert.IsTrue( pe4_3.IsInsideParent( g2_1 ) );
			Assert.IsTrue( g4_3.IsInsideParent( g2_1 ) );
			Assert.IsTrue( g4_3.IsInsideParent( rootGroup ) );

			Assert.IsFalse( pe1_0.IsInsideParent( g2_1 ) );
			Assert.IsFalse( pe4_3.IsInsideParent( g1_1 ) );
			Assert.IsFalse( pe2_1.IsInsideParent( g3_2 ) );
			Assert.IsFalse( g2_1.IsInsideParent( g4_3 ) );
		}

	}
}
