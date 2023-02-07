using System;
using System.IO;
using System.Threading.Tasks;
using System.Management.Automation;
using System.Collections.ObjectModel;

namespace Agent
{
    public static class PS_Invoker
    {
        public static async Task<dynamic> ExecScript(string script, string cmd)
        {
            var powershell = PowerShell.Create();
            // Adding and reading the script
            powershell.AddScript(File.ReadAllText(script), false);
            // Preping the script after adding
            powershell.Invoke();
            powershell.Commands.Clear();
            // Adding the command to call
            powershell.AddCommand(cmd);

            
            PSDataCollection<PSObject> results = await powershell.InvokeAsync();

            dynamic mainObj = results[0];
            return mainObj;
            /*Console.WriteLine(mainObj["RunningServs"].Length);
            for (int i = 0; i < mainObj["RunningServs"].Length; i++)
            {
                Console.WriteLine(mainObj["RunningServs"][i]);
            }*/
        }

        // Overload for commands in the powershell scripts that require a parameter
        public static void ExecScript(string script, string cmd, string param)
        {
            //powershell.AddCommand("Trace-DefenderLogs");
            //powershell.AddCommand("Start-liteScan").AddParameter("Path", QuickScanRoot);
        }
    }
}
