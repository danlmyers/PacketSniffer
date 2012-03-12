/// Event Handling Mechnisms
/// This allows an event to be created from the PacketHandler, then the
/// eventhandler notifies anyone who is plugged into the event to be set
/// off and perform a task.  The entire ProtocolData classes are being
/// sent through the event handle, based on the parent base class of IPData
/// this allows all the classes based on IPData to also be passed through this
/// Event.

using System;

namespace PacketSniffer
{
    public class PacketRecievedEventArgs : EventArgs
    {
        private IPData p_PD;

        public IPData PD
        {
            get { return p_PD; }
        }

        public PacketRecievedEventArgs(IPData PD) 
        {
            p_PD = PD; 
        }
    }

    public class PacketRecieveEvent
    {
        public delegate void PacketRecievedEAD(Object Sender, PacketRecievedEventArgs e);
        public event PacketRecievedEAD PREvent;

        public void fire(IPData PD)
        {
            PacketRecievedEventArgs PRE = new PacketRecievedEventArgs(PD);
            PREvent(this, PRE);
        }
    }
}
