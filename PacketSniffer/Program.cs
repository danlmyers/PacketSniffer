/// *************************************************
/// *   Daniel Myers                                *
/// *   CS206 - Intermediate Programming            *
/// *   Packet Sniffer                              *
/// *                                               *
/// *   This program is a basic level Packet Sniffer*
/// * Currently it only supports IP level ICMP, UDP *
/// * and TCP packet Deciphering.  The Listen mode  *
/// * is in its own thread, it sends a message out  *
/// * that updates the windows form when Packets are*
/// * recieved.                                     *
/// *************************************************

using System;
using System.Windows.Forms;

namespace PacketSniffer
{
    static class Program
    {
        /// <summary>
        /// The main entry point for the application.
        /// </summary>
        [STAThread]
        static void Main()
        {
            Application.EnableVisualStyles();
            Application.SetCompatibleTextRenderingDefault(false);
            Application.Run(new MainWindow());
            
        }
    }
}