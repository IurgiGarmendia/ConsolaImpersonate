using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;



using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Security.Permissions;
using Microsoft.Win32.SafeHandles;
using System.Runtime.ConstrainedExecution;
using System.Security;
using System.IO;

//https://www.codeproject.com/Questions/200044/Copy-file-from-pc-to-server-with-authentication



namespace ConsolaImpersonate
{



    class Program
    {

        [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        public static extern bool LogonUser(String lpszUsername, String lpszDomain, String lpszPassword,
    int dwLogonType, int dwLogonProvider, out SafeTokenHandle phToken);

        [DllImport("kernel32.dll", CharSet = CharSet.Auto)]
        public extern static bool CloseHandle(IntPtr handle);

        // Test harness.
        // If you incorporate this code into a DLL, be sure to demand FullTrust.
        [PermissionSetAttribute(SecurityAction.Demand, Name = "FullTrust")]


        static void Main(string[] args)
        {
            SafeTokenHandle safeTokenHandle;
            try
            {
                string userName, domainName;
                //string ip;
                // Get the user token for the specified user, domain, and password using the
                // unmanaged LogonUser method.
                // The local machine name can be used for the domain name to impersonate a user on this machine.
                Console.Write("Enter the name of the domain on which to log on: ");
                //domainName = Console.ReadLine();
                domainName = "";

                Console.Write("Enter the login of a user on {0} that you wish to impersonate: ", domainName);
                //userName = Console.ReadLine();
                userName = "wes";

                Console.Write("Enter the password for {0}: ", userName);

                const int LOGON32_PROVIDER_DEFAULT = 0;
                //This parameter causes LogonUser to create a primary token.
                const int LOGON32_LOGON_INTERACTIVE = 2;

                // Call LogonUser to obtain a handle to an access token.
                bool returnValue = LogonUser(userName, domainName, Console.ReadLine(),
                    LOGON32_LOGON_INTERACTIVE, LOGON32_PROVIDER_DEFAULT,
                    out safeTokenHandle);

                Console.WriteLine("LogonUser called.");

                

                if (false == returnValue)
                {
                    int ret = Marshal.GetLastWin32Error();
                    Console.WriteLine("LogonUser failed with error code : {0}", ret);
                    throw new System.ComponentModel.Win32Exception(ret);
                }

                //Console.Write("Enter ip: ");
                //ip = Console.ReadLine();

                using (safeTokenHandle)
                {
                    Console.WriteLine("Did LogonUser Succeed? " + (returnValue ? "Yes" : "No"));
                    Console.WriteLine("Value of Windows NT token: " + safeTokenHandle);

                    // Check the identity.
                    Console.WriteLine("Before impersonation: " + WindowsIdentity.GetCurrent().Name);
                    // Use the token handle returned by LogonUser.
                    using (WindowsImpersonationContext impersonatedUser = WindowsIdentity.Impersonate(safeTokenHandle.DangerousGetHandle()))
                    {

                        // Check the identity.
                        Console.WriteLine("After impersonation: " + WindowsIdentity.GetCurrent().Name);
                        //Console.WriteLine("After impersonation (User): " + WindowsIdentity.GetCurrent().User);
                        //Console.WriteLine("After impersonation (Owner): " + WindowsIdentity.GetCurrent().Owner);

                        Console.Write("Folder: ");
                        string folder = Console.ReadLine();


                        string folderPath = @"\\192.168.30.102\IntranetTemporal\"+folder;
                        //string folderPath = @"\\"+ip+@"\Activa";
                        //foreach (string file in Directory.EnumerateFiles(folderPath, "*.rar"))
                        //{

                        //    Console.WriteLine("Archivo : {0}", file);
                        //}


                        // Get list of files in the specific directory.
                        // ... Please change the first argument.
                        string[] files = Directory.GetFiles(folderPath, "*.*", SearchOption.AllDirectories);

                        // Display all the files.
                        foreach (string file in files)
                        {
                            Console.WriteLine(file);
                        }



                    }
                    // Releasing the context object stops the impersonation
                    // Check the identity.
                    Console.WriteLine("After closing the context: " + WindowsIdentity.GetCurrent().Name);
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine("Exception occurred. " + ex.Message);
            }
            Console.ReadLine();
        }
    }
}

public sealed class SafeTokenHandle : SafeHandleZeroOrMinusOneIsInvalid
{
    private SafeTokenHandle()
        : base(true)
    {
    }

    [DllImport("kernel32.dll")]
    [ReliabilityContract(Consistency.WillNotCorruptState, Cer.Success)]
    [SuppressUnmanagedCodeSecurity]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CloseHandle(IntPtr handle);

    protected override bool ReleaseHandle()
    {
        return CloseHandle(handle);
    }

}
