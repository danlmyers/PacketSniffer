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

/// *************************************************
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