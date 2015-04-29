using System;
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Text;

namespace JFIFExtractor
{
    class Program
    {
        // REQUIRED CONSTS

        const int PROCESS_QUERY_INFORMATION = 0x0400;
        const int MEM_COMMIT = 0x00001000;
        const int PAGE_READWRITE = 0x04;
        const int PROCESS_WM_READ = 0x0010;


        // REQUIRED METHODS

        [DllImport("kernel32.dll")]
        public static extern IntPtr OpenProcess(int dwDesiredAccess, bool bInheritHandle, int dwProcessId);

        [DllImport("kernel32.dll")]
        public static extern bool ReadProcessMemory(int hProcess, int lpBaseAddress, byte[] lpBuffer, int dwSize, ref int lpNumberOfBytesRead);

        [DllImport("kernel32.dll")]
        static extern void GetSystemInfo(out SYSTEM_INFO lpSystemInfo);

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern int VirtualQueryEx(IntPtr hProcess, IntPtr lpAddress, out MEMORY_BASIC_INFORMATION lpBuffer, uint dwLength);


        // REQUIRED STRUCTS

        public struct MEMORY_BASIC_INFORMATION
        {
            public int BaseAddress;
            public int AllocationBase;
            public int AllocationProtect;
            public int RegionSize;
            public int State;
            public int Protect;
            public int lType;
        }

        public struct SYSTEM_INFO
        {
            public ushort processorArchitecture;
            ushort reserved;
            public uint pageSize;
            public IntPtr minimumApplicationAddress;
            public IntPtr maximumApplicationAddress;
            public IntPtr activeProcessorMask;
            public uint numberOfProcessors;
            public uint processorType;
            public uint allocationGranularity;
            public ushort processorLevel;
            public ushort processorRevision;
        }

        public static void Main()
        {
            // getting minimum & maximum address

            SYSTEM_INFO sys_info = new SYSTEM_INFO();
            GetSystemInfo(out sys_info);

            IntPtr proc_min_address = sys_info.minimumApplicationAddress;
            IntPtr proc_max_address = sys_info.maximumApplicationAddress;

            // saving the values as long ints so I won't have to do a lot of casts later
            long proc_min_address_l = (long)proc_min_address;
            long proc_max_address_l = (long)proc_max_address;

            Console.Write("Please enter the process name: ");
            String processName = Console.ReadLine();

            Process[] process = Process.GetProcessesByName(processName);

            if(process.Length == 0)
            {
                Console.WriteLine("Process not found.");
                Console.ReadLine();
                return;
            }

            // opening the process with desired access level
            IntPtr processHandle = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_WM_READ, false, process[0].Id);

            // this will store any information we get from VirtualQueryEx()
            MEMORY_BASIC_INFORMATION mem_basic_info = new MEMORY_BASIC_INFORMATION();

            int bytesRead = 0;  // number of bytes read with ReadProcessMemory

            MD5 md5Hash = MD5.Create();

            Directory.CreateDirectory("output");

            while (proc_min_address_l < proc_max_address_l)
            {
                // 28 = sizeof(MEMORY_BASIC_INFORMATION)
                VirtualQueryEx(processHandle, proc_min_address, out mem_basic_info, 28);

                // if this memory chunk is accessible
                if (mem_basic_info.Protect == PAGE_READWRITE && mem_basic_info.State == MEM_COMMIT)
                {
                    byte[] buffer = new byte[mem_basic_info.RegionSize];

                    // read everything in the buffer above
                    if (!ReadProcessMemory((int)processHandle, mem_basic_info.BaseAddress, buffer, mem_basic_info.RegionSize, ref bytesRead))
                    {
                        Console.WriteLine("Reading memory failed!");
                    }

                    // search for JFIF header
                    for (int i = 0; i < mem_basic_info.RegionSize - 30000; ++i)
                    {
                        if (isJFIFHeader(buffer, i))
                        {
                            // search for JPEG file ending
                            for (int j = i+1; j < mem_basic_info.RegionSize; ++j)
                            {
                                // break if another JFIF header is found
                                if (isJFIFHeader(buffer, j))
                                {
                                    break;
                                }

                                // check for JPEG file ending
                                if (buffer[j-1] == 0xFF && buffer[j] == 0xD9)
                                {
                                    int size = j-i+1;
                                    // skip files smaller than 30kb
                                    if (size > 30000)
                                    {
                                        byte[] jfif = new byte[size];
                                        Array.Copy(buffer, i, jfif, 0, size);
                                        string filename = "output/" + GetMd5Hash(md5Hash, jfif) + ".jpg";
                                        File.WriteAllBytes(filename, jfif);
                                    }

                                    i = j;
                                    break;
                                }
                            }
                        }
                    }
                }

                // move to the next memory chunk
                proc_min_address_l += mem_basic_info.RegionSize;
                proc_min_address = new IntPtr(proc_min_address_l);
            }

            Console.WriteLine("Finished extracting files.");
            Console.ReadLine();
        }

        private static bool isJFIFHeader(byte[] b, int i)
        {
            if (b[i+0] == 0xFF && b[i+1] == 0xD8 &&                                                                                             // APP0 marker
                b[i+2] == 0xFF && b[i+3] == 0xE0 && b[i+6] == 0x4A && b[i+7] == 0x46 && b[i+8] == 0x49 && b[i+9] == 0x46 && b[i+10] == 0x00)    // JFIF identifier
            {
                return true;
            }

            return false;
        }

        static string GetMd5Hash(MD5 md5Hash, byte[] input)
        {

            // Convert the input string to a byte array and compute the hash. 
            byte[] data = md5Hash.ComputeHash(input);

            // Create a new Stringbuilder to collect the bytes 
            // and create a string.
            StringBuilder sBuilder = new StringBuilder();

            // Loop through each byte of the hashed data  
            // and format each one as a hexadecimal string. 
            for (int i = 0; i < data.Length; i++)
            {
                sBuilder.Append(data[i].ToString("x2"));
            }

            // Return the hexadecimal string. 
            return sBuilder.ToString();
        }
    }
}
