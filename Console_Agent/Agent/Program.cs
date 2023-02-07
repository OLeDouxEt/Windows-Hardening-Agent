using System;
using System.IO;
using System.Threading.Tasks;
using System.Collections.Generic;

namespace Agent
{
    class Program
    {
        private static string currDir = Directory.GetCurrentDirectory();
        private static string QuickScanRoot = "C:/Users";
        //string script = $"{currDir}\\Powershell_Components\\EventViewer-Component.ps1";
        private static Dictionary<string, string> Scripts = new Dictionary<string, string>()
        {
            {"DefendScript",$"{currDir}\\Powershell_Components\\Defender-Component.ps1"},
            {"EventScript",$"{currDir}\\Powershell_Components\\EventViewer-Component.ps1"},
            {"FWallScript",$"{currDir}\\Powershell_Components\\Firewall-Component.ps1"},
        };

        private static List<string> Cmd = new List<string>() 
        { 
            "Confirm-DefendStatus",
            "Update-VirusSigs",
            "Start-liteScan",
            "Start-QuickScan",
            "Start-FullScan",
            "Search-Threats",
            "Remove-Threats",
            "Test-Function"
        };

        static async Task Main(string[] args)
        {
            dynamic cmdRes = await PS_Invoker.ExecScript(Scripts["DefendScript"], Cmd[0]);
            // Will add logic for parsing this out. Then probably pop this into its own function or class.
            Console.WriteLine(cmdRes.GetType());
            if (cmdRes.GetType() == typeof(bool))
            {
                Console.WriteLine("Its a bool");
            }
            else if(cmdRes.GetType() == typeof(System.Collections.Hashtable)){
                Console.WriteLine("Its a hashtable");
            }
            else
            {
                Console.WriteLine("Its a this is a test");
            }
        }
    }
}
