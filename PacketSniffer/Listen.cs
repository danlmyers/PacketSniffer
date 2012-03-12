/// This is the class that sets the adapter into Promisucus Listen mode.
/// Promisucus mode basically is that any Internet Traffic the Program recieves
/// it processes.  Unfotunately probably due to windows limitations this only
/// includes traffic that is specifically being sent to the adapter being listened
/// with and it's IP address, so it will NOT pick up other traffic on the network


using System;
using System.Net;
using System.Net.Sockets;
using System.Threading;

namespace PacketSniffer
{
    public class Listen
    {
        #region Fields
        private const int p_PacketBufferSize = 65536; // this is the Maximum size that a packet will ever be
        private byte[] p_PacketBuffer = new byte[p_PacketBufferSize]; //Packet Buffer
        private string p_HostIP;
        #endregion //Fields

        private PacketRecieveEvent p_PRE;
        private Socket ListenSocket;
        #region HostIP
        /// <summary>
        /// Set the Adapter that we are Listening On
        /// </summary>
        public string HostIP { set { p_HostIP = value; } }
        #endregion //HostIP

        public Listen(PacketRecieveEvent PRE)
        {
            p_PRE = PRE;
        }

        public void RunReciever()
        {

            ListenSocket = new Socket(AddressFamily.InterNetwork, SocketType.Raw, ProtocolType.IP);
            try
            {
                // Setup the Socket
                ListenSocket.Bind(new IPEndPoint(IPAddress.Parse(p_HostIP), 0));
                ListenSocket.SetSocketOption(SocketOptionLevel.IP, SocketOptionName.HeaderIncluded, 1);
                ListenSocket.IOControl(unchecked((int) 0x98000001), new byte[4] {1, 0, 0, 0}, new byte[4]);
                while (true) //Infinite Loop keeps the Socket in Listen
                {
                    ListenSocket.BeginReceive(p_PacketBuffer, 0, p_PacketBufferSize, SocketFlags.None,
                                                new AsyncCallback(CallReceive), this); 

                    while (ListenSocket.Available == 0) // If no Data Sleep the thread for 1ms then check to see if there is data to be read
                    {
                        Thread.Sleep(1);
                    }
                }
            }
            catch (ThreadAbortException){}// Catch the ThreadAbort Exception that gets generated whenever a thread is closed with the Thread.Abort() method
            catch (Exception e) {new ErrorHandle(e);}
            finally //Shutdown the Socket when finished
            {
                if (ListenSocket != null)
                {
                    ListenSocket.Shutdown(SocketShutdown.Both);
                    ListenSocket.Close();
                }
            }
        }

        protected virtual void CallReceive(IAsyncResult ar)
        {
            new PacketHandler(p_PRE, ref p_PacketBuffer);
        }

    }
}