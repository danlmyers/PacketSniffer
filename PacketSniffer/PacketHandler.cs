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

/// The Packet Handler takes the packetdata from the listen methods
/// and processes it moving all the header data for the Associated
/// protocols into their own Data Class, then passes it to a method
/// that Sets up the Event and Fires a Packet recieved/decoded event
/// to anyone hooked in to listen to it.
using System;
using System.Net;

namespace PacketSniffer
{
    class PacketHandler
    {
        private PacketRecieveEvent PRE;

        public PacketHandler(PacketRecieveEvent p_PRE, ref byte[] PacketData)
        {
            PRE = p_PRE;
            byte p_protocol = PacketData[9];
            try
            {
                switch (p_protocol)
                {
                    case 1:ICMPHandler(ref PacketData);break;
                    case 6:TCPHandler(ref PacketData);break;
                    case 17:UDPHandler(ref PacketData);break;
                    default:break;    
                }
            }
            catch (Exception e) { new ErrorHandle(e); }
        }

        private void TCPHandler(ref byte[] PacketData)
        {
            TCPData TCP = new TCPData();
            IPHandler(TCP, ref PacketData);
            byte[] p_TCPData = new byte[(PacketData.Length - TCP.IP_IHL)];
            Buffer.BlockCopy(PacketData, TCP.IP_IHL, p_TCPData, 0, p_TCPData.Length);
            TCP.TCP_SourcePort = (ushort)IPAddress.NetworkToHostOrder(BitConverter.ToInt16(p_TCPData, 0));
            TCP.TCP_DestinationPort = (ushort)IPAddress.NetworkToHostOrder(BitConverter.ToInt16(p_TCPData, 2));
            TCP.TCP_SequenceNumber = (uint)IPAddress.NetworkToHostOrder(BitConverter.ToInt16(p_TCPData, 4));
            TCP.TCP_AcknowledgementNumber = (uint)IPAddress.NetworkToHostOrder(BitConverter.ToInt16(p_TCPData, 8));
            TCP.TCP_DataOffset = (byte)((p_TCPData[12] >> 4) * 4);
            TCP.TCP_ControlBits = (byte)((p_TCPData[13] & 0x3F));
            TCP.TCP_Window = (ushort)IPAddress.NetworkToHostOrder(BitConverter.ToInt16(p_TCPData, 14));
            TCP.TCP_Checksum = (ushort)(IPAddress.NetworkToHostOrder(BitConverter.ToInt16(p_TCPData, 16)));
            TCP.TCP_UrgentPointer = (ushort)IPAddress.NetworkToHostOrder(BitConverter.ToInt16(p_TCPData, 18));
            if (!((TCP.TCP_DataOffset - 20) <= 0))
            {
                byte[] p_TCPOptions = new byte[TCP.TCP_DataOffset - 20];
                Buffer.BlockCopy(p_TCPData, 20, p_TCPOptions, 0, p_TCPOptions.Length);
                TCP.TCP_OptionsCreate(ref p_TCPOptions);
            }
            if (!((TCP.IP_TotalLength - (TCP.TCP_DataOffset + TCP.IP_IHL)) <= 0))
            {
                byte[] p_DataSend = new byte[TCP.IP_TotalLength - (TCP.TCP_DataOffset + TCP.IP_IHL)];
                Buffer.BlockCopy(p_TCPData, TCP.TCP_DataOffset, p_DataSend, 0, p_DataSend.Length);
                TCP.PacketDataCreate(ref p_DataSend);
                PRE.fire(TCP);
            }else return;
        }
        private void UDPHandler(ref byte[] PacketData)
        {
            UDPData UDP = new UDPData();
            IPHandler(UDP, ref PacketData);
            byte[] p_UDPData = new byte[PacketData.Length - UDP.IP_IHL];
            UDP.UDP_SourcePort = (ushort)IPAddress.NetworkToHostOrder(BitConverter.ToInt16(p_UDPData, 0));
            UDP.UDP_DestinationPort = (ushort)IPAddress.NetworkToHostOrder(BitConverter.ToInt16(p_UDPData, 2));
            UDP.UDP_Length = (ushort)IPAddress.NetworkToHostOrder(BitConverter.ToInt16(p_UDPData, 4));
            UDP.UDP_Checksum = (ushort)IPAddress.NetworkToHostOrder(BitConverter.ToInt16(p_UDPData, 6));
            if (!((UDP.IP_TotalLength - (UDP.IP_IHL + 8)) <= 0))
            {
                byte[] p_DataSend = new byte[UDP.IP_TotalLength - (8 + UDP.IP_IHL)];
                Buffer.BlockCopy(p_UDPData, 8, p_DataSend, 0, p_DataSend.Length);
                UDP.PacketDataCreate(ref p_DataSend);
                PRE.fire(UDP);
            }else return;
        }
        private void ICMPHandler(ref byte[] PacketData)
        {
            ICMPData ICMP = new ICMPData();
            IPHandler(ICMP, ref PacketData);
            byte[] p_ICMPData = new byte[PacketData.Length - ICMP.IP_IHL];
            Buffer.BlockCopy(PacketData, ICMP.IP_IHL, p_ICMPData, 0, p_ICMPData.Length);
            ICMP.ICMP_Type = p_ICMPData[0];
            ICMP.ICMP_Code = p_ICMPData[1];
            ICMP.ICMP_Checksum = (ushort) BitConverter.ToInt16(p_ICMPData, 2);
            if (!((ICMP.IP_TotalLength - (ICMP.IP_IHL + 4)) <= 0))
            {
                byte[] p_DataSend = new byte[ICMP.IP_TotalLength - 4];
                Buffer.BlockCopy(p_ICMPData, 4, p_DataSend, 0, p_DataSend.Length);
                ICMP.PacketDataCreate(ref p_DataSend);
                PRE.fire(ICMP);
            }else return;
        }

        private void IPHandler(IPData IP, ref byte[] PacketData)
        {
            IP.IP_Version = (byte) (PacketData[0] >> 4);
            IP.IP_IHL = (byte) ((PacketData[0] & 0x0F)*4);
            IP.IP_TOS = PacketData[1];
            IP.IP_TotalLength = (ushort) IPAddress.NetworkToHostOrder(BitConverter.ToInt16(PacketData, 2));
            IP.IP_Identification = (ushort) IPAddress.NetworkToHostOrder(BitConverter.ToInt16(PacketData, 4));
            IP.IP_Flags = (byte) ((PacketData[6] & 0xE0) >> 5);
            IP.IP_FragmentOffset = (ushort)(IPAddress.NetworkToHostOrder(BitConverter.ToInt16(PacketData, 6)) & 0x1FFF);
            IP.IP_TimeToLive = PacketData[8];
            IP.IP_Protocol = PacketData[9];
            IP.IP_HeaderChecksum = (ushort)(IPAddress.NetworkToHostOrder(BitConverter.ToInt16(PacketData, 10)));
            IP.SourceIP = new IPAddress(BitConverter.ToInt32(PacketData, 12) & 0x00000000FFFFFFFF);
            IP.DestinationIP = new IPAddress(BitConverter.ToInt32(PacketData, 16) & 0x00000000FFFFFFFF);
        }
    }
}
