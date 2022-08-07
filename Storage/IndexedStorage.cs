using Bitmessage.Cryptography;
using Bitmessage.Global;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;

namespace Bitmessage.Storage
{
    /// <summary>
    /// Provides a disk based simple indexed storage.
    /// Uses lock() statements generously to be thread safe.
    /// </summary>
    /// <remarks>
    /// The storage uses two files, one for the index and one for the data.
    /// The index can be rebuilt from the data if it's ever lost or out of sync.
    /// During operation, the index is kept entirely in memory.
    /// </remarks>
    public class IndexedStorage : IDisposable
    {
        /// <summary>
        /// Size of the hash.
        /// This is identical to the hashes used in the bitmessage network
        /// </summary>
        public const int INDEX_SIZE = 32;

        /// <summary>
        /// File with the database contents
        /// </summary>
        private readonly FileStream dbStream;
        /// <summary>
        /// File that holds the indexes
        /// </summary>
        private readonly FileStream indexStream;

        /// <summary>
        /// Gets the disposal flag
        /// </summary>
        public bool Disposed { get; private set; }
        /// <summary>
        /// Gets the full path and file name for the index file
        /// </summary>
        public string IndexFileName { get; }
        /// <summary>
        /// Gets the full path and file name for the database file
        /// </summary>
        public string DatabaseFileName { get; }

        /// <summary>
        /// Gets the size of the database on disk
        /// </summary>
        public ulong DatabaseSize
        {
            get
            {
                CheckDispose();
                lock (dbStream)
                {
                    return (ulong)dbStream.Length;
                }
            }
        }
        /// <summary>
        /// Gets the number of indexes
        /// </summary>
        /// <remarks>This includes entries marked for removal</remarks>
        public int Count { get => indices.Count; }

        /// <summary>
        /// Memory list of items
        /// </summary>
        private readonly List<DbIndex> indices;

        /// <summary>
        /// Creates a new indexed storage database or loads an existing database
        /// </summary>
        /// <param name="DatabasePathAndName">
        /// Database path and file name.
        /// The index file will have ".idx" appended, the database file ".idb"
        /// </param>
        /// <remarks>
        /// Be careful when specifying relative paths
        /// and check <see cref="Environment.CurrentDirectory"/> first.
        /// </remarks>
        public IndexedStorage(string DatabasePathAndName)
        {
            if (string.IsNullOrWhiteSpace(DatabasePathAndName))
            {
                throw new ArgumentException($"'{nameof(DatabasePathAndName)}' cannot be null or whitespace.", nameof(DatabasePathAndName));
            }

            //Generate absolute file names
            IndexFileName = Path.GetFullPath(DatabasePathAndName + ".idx");
            DatabaseFileName = Path.GetFullPath(DatabasePathAndName + ".idb");

            //File existence check
            var hasIndex = File.Exists(IndexFileName);
            var hasDb = File.Exists(DatabaseFileName);

            if (hasIndex && !hasDb)
            {
                throw new IOException($"Index file {IndexFileName} misses database file {DatabaseFileName}. " +
                    $"You have to delete the index file or recover the database from backup before you can use this database name again.");
            }
            indices = new List<DbIndex>();

            dbStream = File.Open(DatabaseFileName, FileMode.OpenOrCreate, FileAccess.ReadWrite, FileShare.Read);
            indexStream = File.Open(IndexFileName, FileMode.OpenOrCreate, FileAccess.ReadWrite, FileShare.Read);

            if (!hasIndex && hasDb)
            {
                //DB found but not index
                RecoverIndexFromDb();
            }
            else if (hasIndex)
            {
                //DB and index found
                LoadIndexFromDisk();
            }
            else
            {
                //New database. Files left empty
            }
        }

        /// <summary>
        /// Cleans up the in-memory index and saves it to disk
        /// </summary>
        /// <remarks>
        /// Cleaning up means:
        /// Removal of purged entries,
        /// ordering entries by database file offsets,
        /// removing duplicate hashes.
        /// To actually delete purged entries from the database,
        /// use <see cref="TrimDatabase(bool, bool)"/> instead.
        /// </remarks>
        public void SaveIndex()
        {
            CheckDispose();
            lock (indices)
            {
                var Filtered = indices
                    .Where(m => !m.Purge)
                    .Distinct(new DbIndexComparer())
                    .OrderBy(m => m.FileOffset)
                    .ToList();
                indices.Clear();
                indices.AddRange(Filtered);
                lock (indexStream)
                {
                    //Go to start as we simply overwrite all data
                    indexStream.Seek(0, SeekOrigin.Begin);

                    //Avoid fragmentation by precomputing the size.
                    //Indexes are always the same size, so this is quite easy.
                    //Note: Windows and Linux ensure that when you expand a stream this way,
                    //there is no sensitive information in the allocated data blocks on the disk.
                    //Modern file systems support this type of file (sparse file).
                    //Old file systems (for example FAT32) need to be manually cleared by the OS.
                    //This means that the SetLength operation can hang for a while.
                    indexStream.SetLength(DbIndex.INDEX_BINARY_SIZE * indices.Count);
                    using var BW = indexStream.GetNativeWriter();
                    foreach (var entry in indices)
                    {
                        BW.Write(entry.FileOffset);
                        BW.Write(entry.Hash);
                    }
                }
            }
        }

        /// <summary>
        /// Trims the database by purging deleted entries and duplicates
        /// </summary>
        /// <param name="UseMemory">Use memory instead of a temporary file</param>
        /// <param name="Force">
        /// Force trim, even if no entries are marked for removal in the index.
        /// Must be set to true to purge duplicates
        /// when not at least one index is marked for removal.
        /// Duplicates only potentially occur when the file is manually edited.
        /// </param>
        public void TrimDatabase(bool UseMemory, bool Force = false)
        {
            CheckDispose();
            // It's important that this process doesn't corrupts the main database.
            // This is achieved in the following way:
            //
            // 1. The index is saved to remove deleted entries.
            //    Deleted entries are just marked as deleted but not actually blanked in the database.
            //    This is similar to how filesystems work.
            //    Up to this point, an entry can be restored by simply reversing the "deleted" flag.
            //    Saving the index purges all deleted entries and duplicates,
            //    and sorts the remaining entries in the order they appear in the database.
            //
            // 2. The database is locked to prevent changes.
            //    This is simply done to avoid other threads writing to it during this critical operation
            //
            // 3. All referenced entries from the index are copied into a temporary file or into memory.
            //    Whether a file or memory is used depends on the "UseMemory" argument.
            //    This step simply iterates over all indexes and copies the data from the database
            //    into the temporary stream
            //
            // 4. The database is trimmed back to match the temporary file size.
            //    This is theoretically the first step where data loss could occur
            //    if the process terminates unexpectedly.
            //    This step should however never fail because it never increases the file size.
            //    Worst case is that the size stays as big as previously.
            //
            // 5. The temporary stream is rewound and copied over the database.
            //    Alternatively, we could just move the temporary file,
            //    but since the streams are already open, this is the safer way of doing it.
            //
            // 6. The temporary stream is deleted.
            //
            // Note: It's not that problematic if the database corrupts.
            // The database is merely a mirror of the objects in the network,
            // and can simply be recreated by downloading all objects again.

            lock (indices)
            {
                //Don't bother to trim the database if no entries are pending removal
                //Use "Force" argument to override
                if (!Force && !indices.Any(m => m.Purge))
                {
                    return;
                }
                //Saving the index purges deleted entries and sorts them by database file order
                SaveIndex();
                //File name is not needed if UseMemory is in use
                var TempFileName = UseMemory ? null : Path.GetTempFileName();
                try
                {
                    //Open file or memory stream
                    using var TempFile = UseMemory ? (Stream)new MemoryStream() : File.Open(TempFileName, FileMode.Open, FileAccess.ReadWrite, FileShare.None);
                    using var BW = TempFile.GetNativeWriter();
                    //lockout changes to database
                    lock (dbStream)
                    {
                        long offset = 0;
                        using var BR = dbStream.GetNativeReader();
                        foreach (var item in indices)
                        {
                            //Set DB position if needed
                            if (dbStream.Position != item.FileOffset)
                            {
                                dbStream.Seek(item.FileOffset, SeekOrigin.Begin);
                            }
                            //Copy data from DB into temporary stream
                            var data = BR.ReadBytes(BR.ReadInt32());
                            //Make offset reflect new file position
                            item.FileOffset = offset;
                            BW.Write(data.Length);
                            BW.Write(data);
                            offset += sizeof(int) + data.Length;
                        }
                        //Streams should be flushed before they're seeked
                        BW.Flush();
                        TempFile.Flush();
                        //Reset positions and update new database size
                        TempFile.Seek(0, SeekOrigin.Begin);
                        dbStream.Seek(0, SeekOrigin.Begin);
                        dbStream.SetLength(TempFile.Length);
                        //Copy new data over database and make sure data is flushed to disk
                        //before the lock is released
                        TempFile.CopyTo(dbStream);
                        dbStream.Flush();
                        //Saving the index again to save the new offsets
                        SaveIndex();
                    }
                }
                catch
                {
                    //TODO: Find a way to report/fix this
                }
                finally
                {
                    //Delete the temporary file if it's not in memory
                    if (!string.IsNullOrEmpty(TempFileName))
                    {
                        try
                        {
                            File.Delete(TempFileName);
                        }
                        catch
                        {
                            //Don't care
                        }
                    }
                }
            }
        }

        /// <summary>
        /// Checks if the given hash is contained in the storage
        /// </summary>
        /// <param name="Hash">Hash</param>
        /// <param name="IncludePurged">true, to accept hashes marked for removal but not yet purged</param>
        /// <returns>true, if hash found</returns>
        public bool Contains(byte[] Hash, bool IncludePurged)
        {
            lock (indices)
            {
                var item = indices.FirstOrDefault(m => m.CompareHash(Hash));
                return item != null && (IncludePurged || !item.Purge);
            }
        }

        /// <summary>
        /// Get all hashes from the index
        /// </summary>
        /// <param name="IncludingPurged">true, to include hashes marked for removal</param>
        /// <returns>hashes</returns>
        public byte[][] GetAllHashes(bool IncludingPurged)
        {
            lock (indices)
            {
                return indices
                    .Where(m => IncludingPurged || !m.Purge)
                    .Select(m => m.Hash)
                    .ToArray();
            }
        }

        /// <summary>
        /// Gets all items (including those marked for removal) from the database
        /// </summary>
        /// <returns>Item enumerable</returns>
        /// <remarks>
        /// CAUTION! The database is locked until you iterate over the entire enumerable.
        /// Make sure to always enumerate over all items
        /// </remarks>
        public IEnumerable<byte[]> EnumerateAllContent()
        {
            lock (dbStream)
            {
                dbStream.Seek(0, SeekOrigin.Begin);
                using var BR = dbStream.GetNativeReader();
                while (dbStream.Position < dbStream.Length)
                {
                    yield return BR.ReadBytes(BR.ReadInt32());
                }
            }
        }

        /// <summary>
        /// Gets an object from the database
        /// </summary>
        /// <param name="Hash">Object hash</param>
        /// <returns>Object data, null if not found</returns>
        public byte[] GetData(byte[] Hash)
        {
            CheckDispose();
            if (Hash is null)
            {
                throw new ArgumentNullException(nameof(Hash));
            }
            if (Hash.Length != INDEX_SIZE)
            {
                return null;
            }
            DbIndex item;
            lock (indices)
            {
                item = indices.FirstOrDefault(m => m.CompareHash(Hash));
            }
            if (item != null && !item.Purge)
            {
                lock (dbStream)
                {
                    dbStream.Seek(item.FileOffset, SeekOrigin.Begin);
                    using var BR = dbStream.GetNativeReader();
                    return BR.ReadBytes(BR.ReadInt32());
                }
            }
            return null;
        }

        /// <summary>
        /// Adds an object to the database
        /// </summary>
        /// <param name="Data">Object data</param>
        /// <returns>Hash of data</returns>
        /// <remarks>
        /// No data will be added if an existing entry with the same hash exists.
        /// If said entry is marked for removal, the removal mark will be unset.
        /// </remarks>
        public byte[] AddData(byte[] Data)
        {
            CheckDispose();
            if (Data is null)
            {
                throw new ArgumentNullException(nameof(Data));
            }
            var Hash = Hashing.DoubleSha512(Data).Take(INDEX_SIZE).ToArray();
            lock (indices)
            {
                var existing = indices.FirstOrDefault(m => m.CompareHash(Hash));
                if (existing == null)
                {
                    lock (dbStream)
                    {
                        dbStream.Seek(0, SeekOrigin.End);
                        var Index = new DbIndex()
                        {
                            FileOffset = dbStream.Position,
                            Hash = Hash
                        };
                        using var BW = dbStream.GetNativeWriter();
                        BW.Write(Data.Length);
                        BW.Write(Data);
                        BW.Flush();
                        indices.Add(Index);
                    }
                }
                else
                {
                    //If an entry already exists, just make sure it's enabled
                    existing.Purge = false;
                }
            }
            return Hash;
        }

        /// <summary>
        /// Delete an entry from the database
        /// </summary>
        /// <param name="Hash">Entry hash</param>
        /// <returns>true, if deleted. False if not found</returns>
        /// <remarks>
        /// Also returns true if the entry is already marked for removal.
        /// This doesn't actually deletes the entries from the database,
        /// it just marks them for removal in the index.
        /// Use <see cref="TrimDatabase(bool, bool)"/> to purge deleted entries permanently.
        /// </remarks>
        public bool DeleteData(byte[] Hash)
        {
            CheckDispose();
            return SetDataPurge(Hash, true);
        }

        /// <summary>
        /// Removes the delete mark from an entry
        /// </summary>
        /// <param name="Hash">Entry hash</param>
        /// <returns>true, if entry found, false if already purged or not found</returns>
        /// <remarks>
        /// This only works if <see cref="TrimDatabase(bool, bool)"/>
        /// or <see cref="SaveIndex"/> has not yet been called since the call to
        /// <see cref="DeleteData(byte[])"/>.
        /// </remarks>
        public bool UndeleteData(byte[] Hash)
        {
            CheckDispose();
            return SetDataPurge(Hash, false);
        }

        /// <summary>
        /// Sets the purge flag of an index entry
        /// </summary>
        /// <param name="Hash">Entry hash</param>
        /// <param name="Purge">Purge flag value</param>
        /// <returns>true, if entry found in index</returns>
        private bool SetDataPurge(byte[] Hash, bool Purge)
        {
            if (Hash is null)
            {
                throw new ArgumentNullException(nameof(Hash));
            }
            if (Hash.Length != INDEX_SIZE)
            {
                throw new ArgumentException($"Hash must be {INDEX_SIZE} bytes but is {Hash.Length}", nameof(Hash));
            }
            lock (indices)
            {
                var Item = indices.FirstOrDefault(m => m.CompareHash(Hash));
                if (Item != null)
                {
                    Item.Purge = Purge;
                    return true;
                }
            }
            return false;
        }

        /// <summary>
        /// Loads the index from the index file on disk
        /// </summary>
        private void LoadIndexFromDisk()
        {
            using var BR = indexStream.GetNativeReader();
            while (indexStream.Position < indexStream.Length)
            {
                var index = new DbIndex()
                {
                    FileOffset = BR.ReadInt64(),
                    Hash = BR.ReadBytes(INDEX_SIZE)
                };
                indices.Add(index);
            }
        }

        /// <summary>
        /// Recovers the index from the database by reading all values and recomputing the hashes.
        /// </summary>
        private void RecoverIndexFromDb()
        {
            using var BR = dbStream.GetNativeReader();
            using var BW = indexStream.GetNativeWriter();
            while (dbStream.Position < dbStream.Length)
            {
                var index = new DbIndex()
                {
                    FileOffset = dbStream.Position
                };
                index.Hash = Hashing.DoubleSha512(BR.ReadBytes(BR.ReadInt32())).Take(INDEX_SIZE).ToArray();
                indices.Add(index);
                BW.Write(index.FileOffset);
                BW.Write(index.Hash);
            }
        }

        /// <summary>
        /// Checks if <see cref="Dispose"/> has been called
        /// </summary>
        private void CheckDispose()
        {
            if (Disposed)
            {
                throw new ObjectDisposedException(nameof(IndexedStorage));
            }
        }

        /// <summary>
        /// Closes all open database and index streams and disposes this instance
        /// </summary>
        public void Dispose()
        {
            lock (dbStream)
            {
                if (Disposed)
                {
                    return;
                }
                Disposed = true;
                lock (indices)
                {
                    indices.Clear();
                }
                dbStream.Close();
                dbStream.Dispose();
                lock (indexStream)
                {
                    indexStream.Close();
                    indexStream.Dispose();
                }
            }
        }
    }
}
