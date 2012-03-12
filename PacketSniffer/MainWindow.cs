/// The Main Window Class contains all the information necessary
/// to display the Main Program Window and all Associated Information.
/// This class also Serves as the central Hub for processing in the
/// Entire Program.
using System;
using System.Net;
using System.Threading;
using System.Windows.Forms;

namespace PacketSniffer
{
    public partial class MainWindow : Form
    {
        private Thread p_L1;
        private PacketRecieveEvent p_PRE;

        public MainWindow()
        {
            InitializeComponent();
            PopulateIPCombobox();

            p_PRE = new PacketRecieveEvent();
            p_PRE.PREvent += new PacketRecieveEvent.PacketRecievedEAD(Resultboxaddcreate);
        }

        private void PopulateIPCombobox()
        {
            IPAddress[] p_IP = Dns.GetHostAddresses(Dns.GetHostName());
            if (p_IP.Length > 0) for (int i = 0; i < p_IP.Length; i++) IPComboBox.Items.Add(p_IP[i].ToString());
        }

        private void StartButton_Click(Object Sender, EventArgs e)
        {
            if (IPComboBox.Text == ""){ MessageBox.Show("Please Select an IP"); return; }
            StartStopButtonToggle();
            Listen p_listen = new Listen(p_PRE);
            p_listen.HostIP = IPComboBox.Text;
            p_L1 = new Thread(new ThreadStart(p_listen.RunReciever));
            p_L1.Start();
        }

        private void StartStopButtonToggle()
        {
            if (StartButton.Enabled) 
            {
                StartButton.Enabled = false;
                StopButton.Enabled = true;
            }
            else
            {
                StartButton.Enabled = true;
                StopButton.Enabled = false;
            }
        }

        #region ResultBox
        private delegate void Resultboxadd(Object Sender, PacketRecievedEventArgs e);
        public void Resultboxaddcreate(Object Sender, PacketRecievedEventArgs e)
        {
            if (!InvokeRequired) { ResultBox.Items.Insert(0, e.PD.ToString()); return;}
            BeginInvoke(new Resultboxadd(Resultboxaddcreate), new object[] {Sender, e});
        }
        #endregion //ResultBox

        private void StopButton_Click(Object Sender, EventArgs e)
        {
            p_L1.Abort();
            StartStopButtonToggle();
        }

        private void ResetButton_Click(Object Sender, EventArgs e){ ResultBox.Items.Clear(); }

        private void FileExitItem_Click(Object Sender, EventArgs e){ p_L1.Abort(); Close(); }

        private void HelpAboutItem_Click(Object Sender, EventArgs e)
        {
            AboutBox p_AB = new AboutBox();
            p_AB.Show();
        }

        private void MainWindow_Closing(Object Sender, FormClosingEventArgs e){if(p_L1 != null)p_L1.Abort();}
    }
}