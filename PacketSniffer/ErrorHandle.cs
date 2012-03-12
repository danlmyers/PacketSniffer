/// Class for Dealing specifically with Error Messages in Try Catch Finally Blocks
/// There is one regular Constructor that takes the Exception object and displays
/// it. The overloaded Constructor takes the Exception Object and a String and prints
/// Them both out.
using System;
using System.Windows.Forms;

namespace PacketSniffer
{
    public class ErrorHandle
    {
        /// <summary>
        /// Handle Errors direct pass
        /// </summary>
        /// <param name="e">Error Handler, pass Exception e</param>
        public ErrorHandle(Exception e){ MessageBox.Show("Windows doesn't like your code, Exception at: " + e , "Error" , MessageBoxButtons.OK , MessageBoxIcon.Error); }

        /// <summary>
        /// Handle Errors, Exception e and a string if needed
        /// </summary>
        /// <param name="e">Pass Exception e</param>
        /// <param name="handle">String value to print other information</param>
        public ErrorHandle(Exception e, string handle) { MessageBox.Show("Handle: " + handle + "\r\n" + "Exception: " + e, "Error", MessageBoxButtons.OK, MessageBoxIcon.Error); }
    }
}