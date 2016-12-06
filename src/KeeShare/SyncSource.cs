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


using KeePassLib.Keys;
using System.IO;
using KeePassLib.Serialization;
using KeePassLib;

namespace KeeShare
{
	public delegate void SourceEventHandler(object sender, SyncSource source);

	public class SyncSource
	{	
        public static CompositeKey CreateKeyFor(PwEntry entry)
        {
            return CreateKeyFor(entry.Strings.ReadSafe("Password"));
        }

        public static CompositeKey CreateKeyFor(string password)
        {
            CompositeKey key = new CompositeKey();
            key.AddUserKey(new KcpPassword(password));
            return key;
        }

        public static string FileNameFor(PwEntry entry)
        {
            return entry.Strings.ReadSafe("Title") + "_" + entry.Uuid.ToHexString();
        }

		private FileSystemWatcher m_watcher = new FileSystemWatcher();

        public event SourceEventHandler Changed;

		private CompositeKey m_key;
		public CompositeKey Key
		{
			get { return m_key; }
			set { m_key = value; }
		}

		private PwDatabase m_destinationDB;
		public PwDatabase DestinationDB
		{
			get { return this.m_destinationDB; }
		}


		private PwUuid m_sourceEntryUuid = null;
        public PwUuid Uuid
        {
            get { return m_sourceEntryUuid; }
        }

		private string m_location; 
        public string Location
        {
            get{ return m_location; }
        }

		public SyncSource(PwEntry entry, PwDatabase dest)
		{
			m_sourceEntryUuid = entry.Uuid;
			string location = entry.Strings.ReadSafe( KeeShare.SourcePathField);
			if (IOConnectionInfo.FromPath(location).CanProbablyAccess())
			{
				m_location = location;
			}
			Key = CreateKeyFor( entry );
			m_destinationDB = dest;
			m_watcher.Changed += new FileSystemEventHandler( OnChanged );
            m_watcher.Path = Path.GetDirectoryName(m_location);
            m_watcher.NotifyFilter = NotifyFilters.LastWrite | NotifyFilters.CreationTime;
            m_watcher.Filter = Path.GetFileName(m_location);
        }

		/// <summary>
		/// The function checks if the actual SyncSource is similar to the object that would
		/// be created if the given data would be used to create a new SyncSource object.
		/// Similar means that the <c>path</c> and the <c>destination DB</c> are the same.
		/// A different Key is possible!
		/// </summary>
		/// <param name="entry">The entry which holds all information of the SyncSource</param>
		/// <param name="db">The database to which the SyncSource is related.</param>
		/// <returns>True if <c>path</c> and <c>destination DB</c> are the same.</returns>
		public bool IsSimilar(PwEntry entry, PwDatabase db)
		{
			return m_location == entry.Strings.ReadSafe(KeeShare.SourcePathField)
				&& m_destinationDB == db;
		}

		/// <summary>
		/// This function checks if the actual SyncSource (this) represents exactly the same
		/// SyncSource that would occur if we will use the given entry and db to create a new one.
		/// </summary>
		/// <param name="entry">The PwEntry from our db that should represent a SyncSource.</param>
		/// <param name="db">The db which contains the given entry.</param>
		/// <returns>True if (entry + db) will create the same SyncSource object like "this".</returns>
		public bool IsEqual(PwEntry entry, PwDatabase db)
		{
			if (!IsSimilar(entry, db))
			{
				return false;
			}
			IUserKey key1 = new KcpPassword( entry.Strings.ReadSafe( KeeShare.PasswordField ) );
			IUserKey key2 = m_key.GetUserKey( typeof( KcpPassword ) );
			// null is interpreted as equal
			return (key1 == key2 || key1.KeyData.Equals(key2.KeyData));
		}

		/// <summary>
		/// The <c>StartWatch</c>-function enables the FileSystemWatcher to raise
		/// events on observed changes to the specified deltaDB.
		/// </summary>
		public void StartWatch()
		{
            //at first we merge all actual information from the diff container to our actual database
            if (Changed != null) Changed.Invoke(this, this);
			//now we start listen for new changes
			m_watcher.EnableRaisingEvents = true;
		}

		/// <summary>
		/// The <c>StopWatch</c>-function disables the FileSystemWatcher, so no events
		/// will be raised anymore.
		/// </summary>
		public void StopWatch()
		{
			m_watcher.EnableRaisingEvents = false;
		}

		/// <summary>
		/// The OnChanged-Event was catched if the FileSystemWatcher has noticed
		/// some changed to the specified deltaDB
		/// </summary>
		/// <param name="source"></param>
		/// <param name="args"></param>
		public void OnChanged(object source, FileSystemEventArgs args)
		{
            if(Changed != null) Changed.Invoke( source, this );
		}

		
	}
}
