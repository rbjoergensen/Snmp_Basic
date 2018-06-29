using System;
using System.Collections.Generic;
using System.Net;
using System.Text;
using SnmpSharpNet;
using System.IO;

namespace basic_snmp
{
    class Program
    {
        static string path = @".\SnmpDump.txt";

        static void Main(string[] args)
        {
            // Delete file if it exists.
            if (File.Exists(@".\\SnmpDump.txt"))
            {
                File.Delete(@".\\SnmpDump.txt");
            }
            if (args.Length != 3)
            {
                Console.WriteLine("Syntax: SnmpTable.exe <host> <community> <table oid>");
                return;
            }
            Dictionary<String, Dictionary<uint, AsnType>> result = new Dictionary<String, Dictionary<uint, AsnType>>();
            List<uint> tableColumns = new List<uint>();
            AgentParameters param = new AgentParameters(SnmpVersion.Ver2, new OctetString(args[1]));
            IpAddress peer = new IpAddress(args[0]);
            if (!peer.Valid)
            {
                Console.WriteLine("Unable to resolve name or error in address for peer: {0}", args[0]);
                return;
            }
            UdpTarget target = new UdpTarget((IPAddress)peer);
            Oid startOid = new Oid(args[2]);
            startOid.Add(1);
            Pdu bulkPdu = Pdu.GetBulkPdu();
            bulkPdu.VbList.Add(startOid);
            bulkPdu.NonRepeaters = 0;
            bulkPdu.MaxRepetitions = 100;
            Oid curOid = (Oid)startOid.Clone();

            while (startOid.IsRootOf(curOid))
            {
                SnmpPacket res = null;
                try
                {
                    res = target.Request(bulkPdu, param);
                }
                catch (Exception ex)
                {
                    Console.WriteLine("Request failed: {0}", ex.Message);
                    target.Close();
                    return;
                }
                if (res.Version != SnmpVersion.Ver2)
                {
                    Console.WriteLine("Received wrong SNMP version response packet.");
                    target.Close();
                    return;
                }
                if (res.Pdu.ErrorStatus != 0)
                {
                    Console.WriteLine("SNMP agent returned error {0} for request Vb index {1}",
                                      res.Pdu.ErrorStatus, res.Pdu.ErrorIndex);
                    target.Close();
                    return;
                }
                foreach (Vb v in res.Pdu.VbList)
                {
                    curOid = (Oid)v.Oid.Clone();
                    if (startOid.IsRootOf(v.Oid))
                    {
                        uint[] childOids = Oid.GetChildIdentifiers(startOid, v.Oid);
                        uint[] instance = new uint[childOids.Length - 1];
                        Array.Copy(childOids, 1, instance, 0, childOids.Length - 1);
                        String strInst = InstanceToString(instance);
                        uint column = childOids[0];
                        if (!tableColumns.Contains(column))
                            tableColumns.Add(column);
                        if (result.ContainsKey(strInst))
                        {
                            result[strInst][column] = (AsnType)v.Value.Clone();
                        }
                        else
                        {
                            result[strInst] = new Dictionary<uint, AsnType>();
                            result[strInst][column] = (AsnType)v.Value.Clone();
                        }
                    }
                    else
                    {
                        break;
                    }
                }
                if (startOid.IsRootOf(curOid))
                {
                    bulkPdu.VbList.Clear();
                    bulkPdu.VbList.Add(curOid);
                    bulkPdu.NonRepeaters = 0;
                    bulkPdu.MaxRepetitions = 100;
                }
            }
            target.Close();
            if (result.Count <= 0)
            {
                Console.WriteLine("No results returned.\n");
            }
            else
            {
                foreach (uint column in tableColumns)
                {
                    //Console.Write("\tColumn id {0}", column);
                }
                Console.WriteLine("");
                foreach (KeyValuePair<string, Dictionary<uint, AsnType>> kvp in result)
                {
                    //Console.WriteLine("{0}", kvp.Key);
                    string Entry = "";
                    foreach (uint column in tableColumns)
                    {
                        if (kvp.Value.ContainsKey(column))
                        {
                            //Console.WriteLine("\t{0} ({1})", kvp.Value[column].ToString(),SnmpConstants.GetTypeName(kvp.Value[column].Type));
                            Entry += kvp.Value[column].ToString()+";";
                        }
                        else
                        {
                            Console.Write("\t-");
                        }
                    }
                    using (StreamWriter sw = File.AppendText(path))
                    {
                        Console.WriteLine(Entry);
                        sw.WriteLine(Entry);
                    }
                }
            }
        }
        public static string InstanceToString(uint[] instance)
        {
            StringBuilder str = new StringBuilder();
            foreach (uint v in instance)
            {
                if (str.Length == 0)
                    str.Append(v);
                else
                    str.AppendFormat(".{0}", v);
            }
            return str.ToString();
        }
    }
}
