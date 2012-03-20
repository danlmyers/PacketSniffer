/*This file is part of Packet Sniffer
 * Copyright (C) 2009,2010  Daniel Myers dan<at>moird.com
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>
 */

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
