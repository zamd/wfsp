using System;
using System.Diagnostics;
using System.Runtime.ConstrainedExecution;
using System.Runtime.InteropServices;
using System.Security;
using System.Security.Cryptography.X509Certificates;
using System.Security.Principal;
using System.ServiceModel;
using Microsoft.Win32.SafeHandles;

namespace Microsoft.Activities.SecurityPack
{
    internal static class S4UClient
    {
        // Fields
        private static readonly ChannelFactory<IS4UService_dup> ChannelFactory;

        // Methods
        static S4UClient()
        {
            var binding = new NetNamedPipeBinding(NetNamedPipeSecurityMode.Transport);
            var builder = new UriBuilder
            {
                Scheme = Uri.UriSchemeNetPipe,
                Host = "localhost",
                Path = "/s4u/022694f3-9fbd-422b-b4b2-312e25dae2a2"
            };
            string remoteAddress = builder.Uri.ToString();
            ChannelFactory = new ChannelFactory<IS4UService_dup>(binding, remoteAddress);
        }

        private static WindowsIdentity CallService(Func<IS4UService_dup, IntPtr> contractOperation)
        {
            WindowsIdentity identity;
            IS4UService_dup s4UChannel = ChannelFactory.CreateChannel();
            ICommunicationObject obj2 = (ICommunicationObject)s4UChannel;
            bool flag = false;
            try
            {
                IntPtr handle = contractOperation(s4UChannel);
                using (new SafeKernelObjectHandle(handle, true))
                {
                    obj2.Close();
                    flag = true;
                    identity = new WindowsIdentity(handle);
                }
            }
            finally
            {
                if (!flag)
                {
                    obj2.Abort();
                }
            }
            return identity;
        }

        public static WindowsIdentity CertificateLogon(X509Certificate2 certificate)
        {
            return CallService(channel => channel.CertificateLogon(certificate.RawData, Process.GetCurrentProcess().Id));
        }

        public static WindowsIdentity UpnLogon(string upn)
        {
            return CallService(channel => channel.UpnLogon(upn, Process.GetCurrentProcess().Id));
        }

        // Nested Types
        [ServiceContract(Namespace = "http://schemas.microsoft.com/ws/2008/06/identity/wts")]
        private interface IS4UService_dup
        {
            // Methods
            [OperationContract(Action = "urn:IS4UService-CertificateLogon", ReplyAction = "urn:IS4UService-CertificateLogon-Response")]
            IntPtr CertificateLogon(byte[] certData, int pid);
            [OperationContract(Action = "urn:IS4UService-UpnLogon", ReplyAction = "urn:IS4UService-UpnLogon-Response")]
            IntPtr UpnLogon(string upn, int pid);
        }

        private class SafeKernelObjectHandle : SafeHandleZeroOrMinusOneIsInvalid
        {
            // Methods
            public SafeKernelObjectHandle()
                : base(true)
            {
            }

            public SafeKernelObjectHandle(IntPtr handle)
                : this(handle, true)
            {
            }

            public SafeKernelObjectHandle(IntPtr handle, bool takeOwnership)
                : base(takeOwnership)
            {
                base.SetHandle(handle);
            }

            [return: MarshalAs(UnmanagedType.Bool)]
            [SuppressUnmanagedCodeSecurity, ReliabilityContract(Consistency.WillNotCorruptState, Cer.Success), DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
            private static extern bool CloseHandle(IntPtr handle);
            protected override bool ReleaseHandle()
            {
                return CloseHandle(base.handle);
            }
        }
    }
}
