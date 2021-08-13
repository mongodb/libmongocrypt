/*
 * Copyright 2019–present MongoDB, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

using System;
using System.Collections.Generic;
using System.IO;
using System.Reflection;
using System.Runtime.InteropServices;

namespace MongoDB.Libmongocrypt
{
    /// <summary>
    /// LibraryLoader abstracts loading C functions from a shared library across OS
    /// </summary>
    internal class LibraryLoader
    {
        private ISharedLibraryLoader _loader;

        public LibraryLoader()
        {
            if (!Environment.Is64BitProcess)
            {
                throw new PlatformNotSupportedException($"{this.GetType().Namespace} needs to be run in a 64-bit process.");
            }

            // Windows:
            // https://stackoverflow.com/questions/2864673/specify-the-search-path-for-dllimport-in-net
            //
            // See for better ways
            // https://github.com/dotnet/coreclr/issues/930
            // https://github.com/dotnet/corefx/issues/32015
            List<string> candidatePaths = new List<string>();

            // In the nuget package, get the shared library from a relative path of this assembly
            // Also, when running locally, get the shared library from a relative path of this assembly
            var assembly = typeof(LibraryLoader).GetTypeInfo().Assembly;
            var location = assembly.Location;
            string basepath = Path.GetDirectoryName(location);
            candidatePaths.Add(basepath);

            switch (OperatingSystemHelper.CurrentOperatingSystem)
            {
                case OperatingSystemPlatform.MacOS:
                    {
                        string[] suffixPaths = new[]
                        {
                            "../../runtimes/osx/native/",
                            "runtimes/osx/native/",
                            string.Empty
                        };
                        string path = FindLibrary(candidatePaths, suffixPaths, "libmongocrypt.dylib");
                        _loader = new DarwinLibraryLoader(path);
                    }
                    break;
                case OperatingSystemPlatform.Linux:
                    {
                        string[] suffixPaths = new[]
                        {
                            "../../runtimes/linux/native/",
                            "runtimes/linux/native/",
                            string.Empty
                        };
                        string path = FindLibrary(candidatePaths, suffixPaths, "libmongocrypt.so");
                        _loader = new LinuxLibrary(path);
                    }
                    break;
                case OperatingSystemPlatform.Windows:
                    {
                        string[] suffixPaths = new[]
                        {
                            @"..\..\runtimes\win\native\",
                            @".\runtimes\win\native\",
                            string.Empty
                        };
                        string path = FindLibrary(candidatePaths, suffixPaths, "mongocrypt.dll");
                        _loader = new WindowsLibrary(path);
                    }
                    break;
                default:
                    // should not be reached. If we're here, then there is a bug in OperatingSystemHelper
                    throw new PlatformNotSupportedException("Unsupported operating system.");
            }
        }

        private string FindLibrary(IList<string> basePaths, string[] suffixPaths, string library)
        {
            var candidates = new List<string>();
            foreach (var basePath in basePaths)
            {
                foreach (var suffix in suffixPaths)
                {
                    string path = Path.Combine(basePath, suffix, library);
                    if (File.Exists(path))
                    {
                        // TODO - .NET Standard 2.0
                        //Trace.WriteLine("Load path: " + path);
                        return path;
                    }
                    candidates.Add(path);
                }
            }

            throw new FileNotFoundException("Could not find: " + library + " --\n Tried: " + string.Join(",", candidates));
        }

        public T GetFunction<T>(string name)
        {
            IntPtr ptr = _loader.GetFunction(name);
            if (ptr == IntPtr.Zero)
            {
                throw new FunctionNotFoundException(name);
            }

            return Marshal.GetDelegateForFunctionPointer<T>(ptr);

        }

        public class FunctionNotFoundException : Exception
        {
            public FunctionNotFoundException(string message) : base(message) { }
        }

        private interface ISharedLibraryLoader
        {
            IntPtr GetFunction(string name);
        }

        /// <summary>
        /// macOS Dynamic Library loader using dlsym
        /// </summary>
        private class DarwinLibraryLoader : ISharedLibraryLoader
        {

            // See dlfcn.h
            // #define RTLD_LAZY       0x1
            // #define RTLD_NOW        0x2
            // #define RTLD_LOCAL      0x4
            // #define RTLD_GLOBAL     0x8
            public const int RTLD_GLOBAL = 0x8;
            public const int RTLD_NOW = 0x2;

            private readonly IntPtr _handle;
            public DarwinLibraryLoader(string path)
            {
                _handle = dlopen(path, RTLD_GLOBAL | RTLD_NOW);
                if (_handle == IntPtr.Zero)
                {
                    throw new FileNotFoundException(path);
                }
            }

            public IntPtr GetFunction(string name)
            {
                return dlsym(_handle, name);
            }

#pragma warning disable IDE1006 // Naming Styles
            [DllImport("libdl")]
            public static extern IntPtr dlopen(string filename, int flags);

            [DllImport("libdl", CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Ansi)]
            public static extern IntPtr dlsym(IntPtr handle, string symbol);
#pragma warning restore IDE1006 // Naming Styles
        }

        /// <summary>
        /// Linux Shared Object loader using dlsym
        /// </summary>
        private class LinuxLibrary : ISharedLibraryLoader
        {
            // See dlfcn.h
            // #define RTLD_LAZY       0x1
            // #define RTLD_NOW        0x2
            // #define RTLD_LOCAL      0x4
            // #define RTLD_GLOBAL     0x100
            public const int RTLD_GLOBAL = 0x100;
            public const int RTLD_NOW = 0x2;

            private readonly IntPtr _handle;
            public LinuxLibrary(string path)
            {
                _handle = dlopen(path, RTLD_GLOBAL | RTLD_NOW);
                if (_handle == IntPtr.Zero)
                {
                    throw new FileNotFoundException(path);
                }
            }

            public IntPtr GetFunction(string name)
            {
                return dlsym(_handle, name);
            }

#pragma warning disable IDE1006 // Naming Styles
            [DllImport("libdl")]
            public static extern IntPtr dlopen(string filename, int flags);

            [DllImport("libdl", CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Ansi)]
            public static extern IntPtr dlsym(IntPtr handle, string symbol);
#pragma warning restore IDE1006 // Naming Styles
        }

        /// <summary>
        /// Windows DLL loader using GetProcAddress
        /// </summary>
        private class WindowsLibrary : ISharedLibraryLoader
        {
            private readonly IntPtr _handle;
            public WindowsLibrary(string path)
            {
                _handle = LoadLibrary(path);
                if (_handle == IntPtr.Zero)
                {
                    var gle = Marshal.GetLastWin32Error();

                    // error code 193 indicates that a 64-bit OS has tried to load a 32-bit dll
                    // https://docs.microsoft.com/en-us/windows/win32/debug/system-error-codes--0-499-
                    throw new LibraryLoadingException(path + ", Windows Error: " + gle);
                }
            }

            public IntPtr GetFunction(string name)
            {
                var ptr = GetProcAddress(_handle, name);
                if (ptr == null)
                {
                    var gle = Marshal.GetLastWin32Error();
                    throw new FunctionNotFoundException(name + ", Windows Error: " + gle);
                }

                return ptr;
            }

            [DllImport("kernel32", SetLastError = true, CharSet = CharSet.Ansi)]
            public static extern IntPtr LoadLibrary([MarshalAs(UnmanagedType.LPStr)] string lpFileName);

            [DllImport("kernel32", CharSet = CharSet.Ansi, ExactSpelling = true, SetLastError = true)]
            public static extern IntPtr GetProcAddress(IntPtr hModule, string procName);
        }
    }
}
