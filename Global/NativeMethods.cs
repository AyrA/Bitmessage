using System;
using System.Runtime.InteropServices;
using System.Text.RegularExpressions;

namespace Bitmessage.Global
{
    /// <summary>
    /// Contains methods that need/contain system native implementations
    /// </summary>
    public static class NativeMethods
    {
        // About native functions and .NET
        // ===============================
        // .NET (at least on Windows) will delay load libraries (managed and unmanaged).
        // This reduces startup time and completely avoids DLL loads
        // if you don't use their functions at all.
        //
        // When a DLL is loaded
        // --------------------
        // A DLL is loaded when you enter the function that contains a call into the DLL
        // regardless of whether said call is actually used or not.
        //
        // How to deal with multiple platforms
        // -----------------------------------
        // DLL files are a Windows only thing. This means a solution is needed,
        // if the software is supposed to run on multiple platforms.
        // Trying to load a wrong library will mainly have two possible outcomes:
        //
        // BadImageFormatException: Occurs when you try to load an incompatible file.
        // For example trying to load an x64 DLL in a .NET program running in x86 mode.
        //
        // DllNotFoundException: The DLL file cannot be found
        //
        // The solution for these errors is to implement a backup strategy.
        // When the error is caught, the backup method is activated.

        #region native imports

        [DllImport("msvcrt")]
        private static extern int memcmp(
            [In] byte[] a,
            [In] byte[] b,
            int length);

        [DllImport("BitMsgHash", CallingConvention = CallingConvention.Cdecl)]
        private static extern ulong BitmessagePOW([In] byte[] Buffer, ulong Target);

        [return: MarshalAs(UnmanagedType.Bool)]
        [DllImport("kernel32", CharSet = CharSet.Auto, EntryPoint = "GlobalMemoryStatusEx", SetLastError = true)]
        private static extern bool GlobalMemoryStatusEx(ref MEMORYSTATUSEX lpBuffer);

        #endregion

        #region native structures

        /// <summary>
        /// contains information about the current state of both physical and virtual memory, including extended memory
        /// </summary>
        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Auto)]
        public class MEMORYSTATUSEX
        {
            /// <summary>
            /// Size of the structure, in bytes.
            /// You must set this member before calling GlobalMemoryStatusEx.
            /// </summary>
            public uint dwLength;

            /// <summary>
            /// Number between 0 and 100 that specifies the approximate percentage
            /// of physical memory that is in use
            /// (0 indicates no memory use and 100 indicates full memory use).
            /// </summary>
            public uint dwMemoryLoad;

            /// <summary>
            /// Total size of physical memory, in bytes.
            /// </summary>
            public ulong ullTotalPhys;

            /// <summary>
            /// Size of physical memory available, in bytes.
            /// </summary>
            public ulong ullAvailPhys;

            /// <summary>
            /// Size of the committed memory limit, in bytes.
            /// This is physical memory plus the size of the page file, minus a small overhead.
            /// </summary>
            public ulong ullTotalPageFile;

            /// <summary>
            /// Size of available memory to commit, in bytes.
            /// The limit is ullTotalPageFile.
            /// </summary>
            public ulong ullAvailPageFile;

            /// <summary>
            /// Total size of the user mode portion of the virtual address space
            /// of the calling process, in bytes.
            /// </summary>
            public ulong ullTotalVirtual;

            /// <summary>
            /// Size of unreserved and uncommitted memory in the user mode portion
            /// of the virtual address space of the calling process, in bytes.
            /// </summary>
            public ulong ullAvailVirtual;

            /// <summary>
            /// Size of unreserved and uncommitted memory in the extended portion
            /// of the virtual address space of the calling process, in bytes.
            /// </summary>
            public ulong ullAvailExtendedVirtual;

            /// <summary>
            /// Initializes a new instance of the <see cref="MEMORYSTATUSEX"/> class.
            /// </summary>
            public MEMORYSTATUSEX()
            {
                dwLength = (uint)Marshal.SizeOf(typeof(MEMORYSTATUSEX));
            }
        }

        #endregion

        /// <summary>
        /// Gets whether the fast or slow byte compare routine is in use
        /// </summary>
        /// <remarks>
        /// This is only set to true after the first call to
        /// <see cref="CompareBytes(byte[], byte[])"/> fails to use the fast method.
        /// </remarks>
        public static bool UsingSlowByteCompare { get; private set; } = false;
        /// <summary>
        /// Gets whether the fast or slow POW algorithm is in use
        /// </summary>
        /// <remarks>
        /// This is only set to true after the first call to
        /// <see cref="DoPOW(byte[], ulong)"/> fails to use the fast method.
        /// </remarks>
        public static bool UsingSlowPOW { get; private set; } = false;

        /// <summary>
        /// Gets free system memory in bytes
        /// </summary>
        /// <returns>free system memory</returns>
        /// <remarks>
        /// If it fails to get the memory for any reason it returns zero</remarks>
        public static ulong GetFreeMemory()
        {
            if (Environment.OSVersion.Platform == PlatformID.Win32NT)
            {
                return GetFreeMemoryWindows();
            }
            foreach (var line in System.IO.File.ReadAllLines("/proc/meminfo"))
            {
                if (line.Trim().ToLower().StartsWith("memfree:"))
                {
                    var m = Regex.Match(line.Trim(), @"(\d+)\s+(\w+)$");
                    if (m.Success)
                    {
                        if(!ulong.TryParse(m.Groups[1].Value, out ulong mem))
                        {
                            return 0;
                        }
                        return m.Groups[2].Value.ToLower()[0] switch
                        {
                            'b' => mem,
                            'k' => mem * 1000,
                            'm' => mem * 1000 * 1000,
                            'g' => mem * 1000 * 1000 * 1000,
                            't' => mem * 1000 * 1000 * 1000 * 1000,
                            _ => 0,
                        };
                    }
                }
            }
            return 0;

        }

        /// <summary>
        /// Compute POW for a hash
        /// </summary>
        /// <param name="hash">Hash</param>
        /// <param name="targetDifficulty">
        /// Target difficulty.
        /// This number is obtained with <see cref="POW.GetTargetPOWValue(byte[], uint, uint)"/>
        /// </param>
        /// <returns>POW Nonce</returns>
        public static ulong DoPOW(byte[] hash, ulong targetDifficulty)
        {
            if (UsingSlowPOW)
            {
                //TODO: implement managed POW if native POW module is not available
                throw new PlatformNotSupportedException($"The native POW module is not available on {Environment.OSVersion.Platform}, and no C# backup has been implemented yet.");
            }
            try
            {
                return DoFastPOW(hash, targetDifficulty);
            }
            catch (BadImageFormatException)
            {
                UsingSlowPOW = true;
                return DoPOW(hash, targetDifficulty);
            }
            catch (DllNotFoundException)
            {
                UsingSlowPOW = true;
                return DoPOW(hash, targetDifficulty);
            }
        }

        /// <summary>
        /// Compares two byte arrays for equality
        /// </summary>
        /// <param name="a">Array A</param>
        /// <param name="b">Array B</param>
        /// <returns>true, if contents are equal</returns>
        public static bool CompareBytes(byte[] a, byte[] b)
        {
            //Either one null
            if (a == null && b != null)
            {
                return false;
            }
            if (a != null && b == null)
            {
                return false;
            }
            //Identical references or both null
            if (ReferenceEquals(a, b))
            {
                return true;
            }
            //Different length
            if (a.Length != b.Length)
            {
                return false;
            }
            //Zero length data
            if (a.Length == 0 && b.Length == 0)
            {
                return true;
            }
            if (UsingSlowByteCompare)
            {
                for (var i = 0; i < a.Length; i++)
                {
                    if (a[i] != b[i])
                    {
                        return false;
                    }
                }
                return true;
            }
            else
            {
                //Save yourself a function call if the first byte is already different.
                if (a[0] != b[0])
                {
                    return false;
                }
                try
                {
                    return FastByteCompare(a, b);
                }
                catch (BadImageFormatException)
                {
                    UsingSlowByteCompare = true;
                    return CompareBytes(a, b);
                }
                catch (DllNotFoundException)
                {
                    UsingSlowByteCompare = true;
                    return CompareBytes(a, b);
                }
            }
        }

        /// <summary>
        /// Gets free memory on Windows
        /// </summary>
        /// <returns>Free memory in bytes</returns>
        private static ulong GetFreeMemoryWindows()
        {
            var buffer = new MEMORYSTATUSEX();
            return GlobalMemoryStatusEx(ref buffer) ? buffer.ullAvailPhys : 0;
        }

        /// <summary>
        /// Computes POW using fast C library
        /// </summary>
        /// <param name="hash">Hash</param>
        /// <param name="targetDifficulty">Target difficulty</param>
        /// <returns>Nonce</returns>
        private static ulong DoFastPOW(byte[] hash, ulong targetDifficulty)
        {
            return BitmessagePOW(hash, targetDifficulty);
        }

        /// <summary>
        /// Performs a fast byte array compare using external C library
        /// </summary>
        /// <param name="a">Byte array A</param>
        /// <param name="b">Byte array B</param>
        /// <returns>true, if identical contents</returns>
        private static bool FastByteCompare(byte[] a, byte[] b)
        {
            return memcmp(a, b, a.Length) == 0;
        }
    }
}
