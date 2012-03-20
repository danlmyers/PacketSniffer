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

/// These Classes just contain variables and variable management
/// for IP Packets, TCP, UDP and ICMP packets/Messages.

using System;
using System.Net;
using System.Text.RegularExpressions;
using System.Text;

namespace PacketSniffer
{
    public abstract class IPData
    {
        #region Fields
        private byte p_IP_Version;
        private byte p_IP_IHL;
        private byte p_IP_TOS;
        private ushort p_IP_TotalLength;
        private ushort p_IP_Identification;
        private byte p_IP_Flags;
        private ushort p_IP_FragmentOffset;
        private byte p_IP_TimeToLive;
        private byte p_IP_Protocol;
        private ushort p_IP_HeaderChecksum;
        private byte[] p_PacketData;
        #endregion // Fields

        #region Properties
        #region IP_Version
        /// <summary>
        /// Identifies the version of IP used to enerate the datagram, for IPv4 this will equal 4
        /// </summary>
        public byte IP_Version
        {
            get { return p_IP_Version; }
            set { p_IP_Version = value; }
        }
        #endregion //IP_Version
        #region IP_IHL
        /// <summary>
        /// Specifies the Length of the IP header in 32bit words
        /// </summary>
        public byte IP_IHL
        {
            get { return p_IP_IHL; }
            set { p_IP_IHL = value; }
        }
        #endregion //IP_IHL
        #region IP_TOS
        /// <summary>
        /// IP Datagram Type of Service Field
        /// </summary>
        public byte IP_TOS
        {
            get { return p_IP_TOS; }
            set { p_IP_TOS = value; }
        }
        #endregion //IP_TOS
        #region IP_TotalLength
        /// <summary>
        /// Specifies the length of the IP datagram
        /// </summary>
        public ushort IP_TotalLength
        {
            get { return p_IP_TotalLength; }
            set { p_IP_TotalLength = value; }
        }
        #endregion //IP_TotalLength
        #region IP_IDentification
        /// <summary>
        /// This field contains a 16bit value that is common to each fragment
        /// Only used for IP Datagram Fragmentation
        /// </summary>
        public ushort IP_Identification
        {
            get { return p_IP_Identification; }
            set { p_IP_Identification = value; }
        }
        #endregion //IP_Identification
        #region IP_Flags
        /// <summary>
        /// Three control Flags, two of which are used to manage fragmentation and one that is reserved
        /// </summary>
        public byte IP_Flags
        {
            get { return p_IP_Flags; }
            set { p_IP_Flags = value; }
        }
        #endregion //IP_Flags
        #region IP_FragmentOffset
        /// <summary>
        /// When an IP Datagram is fragmented this field specifies the offset, 
        /// or position in the message where the data in this fragment goes
        /// </summary>
        public ushort IP_FragmentOffset
        {
            get { return p_IP_FragmentOffset; }
            set { p_IP_FragmentOffset = value; }
        }
        #endregion //IP_FragmentOffset
        #region IP_TimeToLive
        /// <summary>
        /// This specifies how long the datagram is allowed to live on the network in router hops
        /// </summary>
        public byte IP_TimeToLive
        {
            get { return p_IP_TimeToLive; }
            set { p_IP_TimeToLive = value; }
        }
        #endregion //IP_TimeToLive
        #region IP_Protocol
        /// <summary>
        /// Identifies the higher-layer protocol carried in the datagram
        /// </summary>
        public byte IP_Protocol
        {
            get { return p_IP_Protocol; }
            set { p_IP_Protocol = value; }
        }
        #endregion IP_Protocol
        #region IP_HeaderChecksum
        /// <summary>
        /// A checksum that is computed over the header to provide basic
        /// protection against corruption in transmission
        /// </summary>
        public ushort IP_HeaderChecksum
        {
            get { return p_IP_HeaderChecksum; }
            set { p_IP_HeaderChecksum = value; }
        }
        #endregion //IP_HeaderChecksum
        #endregion // Properties

        public IPAddress SourceIP;
        public IPAddress DestinationIP;

        #region PacketData Array Management
        public byte[] PacketDataGet(){ return p_PacketData; }
        public byte PacketDataGetByIndex(ref int i){ return p_PacketData[i]; }
        public void PacketDataCreate(ref byte[] PacketData)
        {
            p_PacketData = new byte[PacketData.Length];
            Buffer.BlockCopy(PacketData, 0, p_PacketData, 0, PacketData.Length);
        }
        public void PacketDataSetByIndex(ref int i, ref byte data){ p_PacketData[i] = data; }
        #endregion // PacketData Array Management
    }

    public class TCPData : IPData
    {
        #region Fields
        private ushort p_TCP_SourcePort;
        private ushort p_TCP_DestinationPort;
        private uint p_TCP_SequenceNumber;
        private uint p_TCP_AcknowledgementNumber;
        private byte p_TCP_DataOffset;
        private byte p_TCP_ControlBits;
        private ushort p_TCP_Window;
        private ushort p_TCP_Checksum;
        private ushort p_TCP_UrgentPointer;
        private byte[] p_TCP_Options;
        #endregion //Fields

        #region Properties
        #region TCP_SourcePort
        /// <summary>
        /// This is the port number of the process that originated the TCP segment on the source device
        /// </summary>
        public ushort TCP_SourcePort
        {
            get { return p_TCP_SourcePort; }
            set { p_TCP_SourcePort = value; }
        }
        #endregion //TCP_SourcePort
        #region TCP_DestinationPort
        /// <summary>
        /// This is the port number of the process that is the ultimate intended
        /// recipient of the message on the destination device
        /// </summary>
        public ushort TCP_DestinationPort
        {
            get { return p_TCP_DestinationPort; }
            set { p_TCP_DestinationPort = value; }
        }
        #endregion //TCP_DestinationPort
        #region TCP_SequenceNumber
        /// <summary>
        /// For normal transmissions this is the sequence number of the first byte of data in this segment
        /// </summary>
        public uint TCP_SequenceNumber
        {
            get { return p_TCP_SequenceNumber; }
            set { p_TCP_SequenceNumber = value; }
        }
        #endregion //TCP_SequenceNumber
        #region TCP_AcknowledgementNumber
        /// <summary>
        /// When the ACK bit is set, this segment is serving as an acknowledgement
        /// and this field contains the sequence number the source is next expecting 
        /// the destination to send
        /// </summary>
        public uint TCP_AcknowledgementNumber
        {
            get { return p_TCP_AcknowledgementNumber; }
            set { p_TCP_AcknowledgementNumber = value; }
        }
        #endregion //TCP_AcknowledgementNumber
        #region TCP_DataOffset
        /// <summary>
        /// This field indicates how many 32bit words the start of the data is offset
        /// from the beginning of the TCP segment
        /// </summary>
        public byte TCP_DataOffset
        {
            get { return p_TCP_DataOffset; }
            set { p_TCP_DataOffset = value; }
        }
        #endregion //TCP_DataOffset
        #region TCP_ControlBits
        /// <summary>
        /// TCP does not use a separate format for control messages.  Instead, certain 
        /// bits are set to indicate the communication of control information
        /// </summary>
        public byte TCP_ControlBits
        {
            get { return p_TCP_ControlBits; }
            set { p_TCP_ControlBits = value; }
        }
        #endregion //TCP_ControlBits
        #region TCP_Window
        /// <summary>
        /// This indicates the number of octets of data the sender of this segment
        /// is willing to accept from the receiver at one time.
        /// </summary>
        public ushort TCP_Window
        {
            get { return p_TCP_Window; }
            set { p_TCP_Window = value; }
        }
        #endregion //TCP_Window
        #region TCP_Checksum
        /// <summary>
        /// This is a 16-bit checksum for data integrity protection, computed over 
        /// the entire tcp datagram plus a special pseudo header of fields
        /// </summary>
        public ushort TCP_Checksum
        {
            get { return p_TCP_Checksum; }
            set { p_TCP_Checksum = value; }
        }
        #endregion //TCP_Checksum
        #region TCP_UrgentPointer
        /// <summary>
        /// This is used in conjunction with the URG control bit for priority of data transfer.
        /// </summary>
        public ushort TCP_UrgentPointer
        {
            get { return p_TCP_UrgentPointer; }
            set { p_TCP_UrgentPointer = value; }
        }
        #endregion //TCP_UrgentPointer
        #endregion //Properties

        #region TCP_Options Array Management
        public byte[] TCP_OptionsGet() { return p_TCP_Options; }
        public byte TCP_OptionsGetByIndex(ref int i) { return p_TCP_Options[i]; }
        public void TCP_OptionsCreate(ref byte[] TCP_Options)
        {
            p_TCP_Options = new byte[TCP_Options.Length];
            Buffer.BlockCopy(TCP_Options, 0, p_TCP_Options, 0, TCP_Options.Length);
        }
        public void TCP_OptionsSetByIndex(ref int i, ref byte data) { p_TCP_Options[i] = data; }
        #endregion //TCP_Options Array Management

        public override string ToString()
        {
            string p_SourceIP = SourceIP.ToString();
            string p_DestinationIP = DestinationIP.ToString();
            string Data = Regex.Replace(Encoding.ASCII.GetString(PacketDataGet()), @"[^a-zA-Z_0-9\.\@\- ]", "");
            return ("TCP " + p_SourceIP + ":" + TCP_SourcePort + " --> " + p_DestinationIP + " : " + TCP_SourcePort + "-->" + Data);
        }
    }

    public class ICMPData : IPData
    {
        #region Fields
        private byte p_ICMP_Type;
        private byte p_ICMP_Code;
        private ushort p_ICMP_Checksum;
        #endregion //Fields

        #region Properties
        #region ICMP_Type
        /// <summary>
        /// Identifies the ICMP message Type
        /// </summary>
        public byte ICMP_Type
        {
            get { return p_ICMP_Type; }
            set { p_ICMP_Type = value; }
        }
        #endregion //ICMP_Type
        #region ICMP_Code
        /// <summary>
        /// Identifies the subtype of message within each ICMP message Type Value
        /// </summary>
        public byte ICMP_Code
        {
            get { return p_ICMP_Code; }
            set { p_ICMP_Code = value; }
        }
        #endregion //ICMP_Code
        #region ICMP_Checksum
        /// <summary>
        /// A 16 bit checksum field that is calculaed in a manner similar to the IP header checksum
        /// </summary>
        public ushort ICMP_Checksum
        {
            get { return p_ICMP_Checksum; }
            set { p_ICMP_Checksum = value; }
        }
        #endregion
        #endregion //Properties

        public string GetICMPTypeString()
        {
            switch(ICMP_Type)
            {
                case 0: return "ICMPEchoReply";
                case 3: return "ICMPDestinationUnreachable";
                case 4: return "ICMPSourceQuench";
                case 5: return "ICMPRedirect";
                case 8: return "ICMPEcho";
                case 11: return "ICMPTimeExceeded";
                case 12: return "ICMPParameterProblem";
                case 13: return "ICMPTimeStamp";
                case 14: return "ICMPTimeStampReply";
                case 15: return "ICMPInformationRequest";
                case 16: return "ICMPInformationReply";
                default: return "ICMP";
            }
        }

        public override string ToString()
        {
            string p_SourceIP = SourceIP.ToString();
            string p_DestinationIP = DestinationIP.ToString();
            string Data = Regex.Replace(Encoding.ASCII.GetString(PacketDataGet()), @"[^a-zA-Z_0-9\.\@\- ]", "");
            return (GetICMPTypeString() + " " + p_SourceIP + " --> " + p_DestinationIP + "--" + Data);
        }
    }

    public class UDPData : IPData
    {
        #region Fields
        private ushort p_UDP_SourcePort;
        private ushort p_UDP_DestinationPort;
        private ushort p_UDP_Length;
        private ushort p_UDP_Checksum;
        #endregion //Fields

        #region Properties
        #region UDP_SourcePort
        /// <summary>
        /// The 16-bit port number of the process that originated the UDP message on the source device
        /// </summary>
        public ushort UDP_SourcePort
        {
            get { return p_UDP_SourcePort; }
            set{ p_UDP_SourcePort = value; }
        }
        #endregion //UDP_SourcePort
        #region UDP_DestinationPort
        /// <summary>
        /// The 16-bit port number of the process that is the ultimate intended recipient of the message on the destination device
        /// </summary>
        public ushort UDP_DestinationPort
        {
            get { return p_UDP_DestinationPort; }
            set{ p_UDP_DestinationPort = value; }
        }
        #endregion //UDP_DestinationPort
        #region UDP_Length
        /// <summary>
        /// The length of the entire UDP datagram, including both the header and Data fields
        /// </summary>
        public ushort UDP_Length
        {
            get { return p_UDP_Length; }
            set{ p_UDP_Length = value; }
        }
        #endregion // UDP_Length
        #region UDP_Checksum
        /// <summary>
        /// An optional 16-bit checksum computed over the entire UDP datagram plus a special pseudo header of fields
        /// </summary>
        public ushort UDP_Checksum
        {
            get { return p_UDP_Checksum; }
            set{ p_UDP_Checksum = value; }
        }
        #endregion //UDP_Checksum
        #endregion //Properties

        public override string ToString()
        {
            string p_SourceIP = SourceIP.ToString();
            string p_DestinationIP = DestinationIP.ToString();
            string Data = Regex.Replace(Encoding.ASCII.GetString(PacketDataGet()), @"[^a-zA-Z_0-9\.\@\- ]", "");
            return ("UDP " + p_SourceIP + ":" + UDP_SourcePort + " --> " + p_DestinationIP + " : " + UDP_DestinationPort + "-->" + Data);
        }
    }
}
