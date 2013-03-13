using System;
using System.Activities.Tracking;
using System.ServiceModel;
using System.ServiceModel.Activities;
using System.ServiceModel.Description;
using System.Text;
using System.Xml;

namespace Extensions.Utilities
{
    public static class ServiceHostBaseExtensions
    {
        static ServiceMetadataBehavior CreateOrRemoveMetadataBehavior(ServiceHostBase host)
        {
            var metadataBv = host.Description.Behaviors.Remove<ServiceMetadataBehavior>();
            if (metadataBv == null)
                metadataBv = new ServiceMetadataBehavior();
            return metadataBv;
        }

        public static void ConfigureMetadataViaHttpGet(this ServiceHostBase source)
        {
            ConfigureMetadataViaHttpGet(source, "");
        }

        public static void ConfigureMetadataViaHttpGet(this ServiceHostBase source, string url)
        {
            var metadataBv = CreateOrRemoveMetadataBehavior(source);

            metadataBv.HttpGetEnabled = true;
            if (!string.IsNullOrEmpty(url))
                metadataBv.HttpGetUrl = new Uri(url);

            source.Description.Behaviors.Add(metadataBv);

        }

        public static void ConfigureMetadataViaMex(this ServiceHostBase source, string address)
        {
            var metadataBv = CreateOrRemoveMetadataBehavior(source);
            source.Description.Behaviors.Add(metadataBv);

            source.AddServiceEndpoint("IMetadataExchange", MetadataExchangeBindings.CreateMexHttpBinding(), address);
        }

        public static string WriteEndpoints(this ServiceHostBase source)
        {
            var sb = new StringBuilder();
            int counter = 0;

            sb.Append("\nHost information:");
            sb.Append("\n-----------------\n\n");
            foreach (var ep in source.Description.Endpoints)
            {
                sb.Append(string.Format("{0}>> ListenUri: {1}\n", ++counter, ep.ListenUri.ToString()));
                sb.Append(string.Format("Name: {0}, Endpoint Address: {1} Binding: {2}\r\n", ep.Name, ep.Address.ToString(), ep.Binding.ToString()));
            }
            var meta = source.Description.Behaviors.Find<ServiceMetadataBehavior>();
            if (meta != null && meta.HttpGetEnabled)
            {
                var metaUrl = meta.HttpGetUrl != null ? meta.HttpGetUrl : source.BaseAddresses[0];
                sb.Append("*>> Http metadata URL: " + metaUrl + "\n");
            }

            return sb.ToString();

        }

        public static void WriteEndpointsBinding(this ServiceHostBase source)
        {
            var orignal = Console.ForegroundColor;
            Console.ForegroundColor = ConsoleColor.Cyan;
            int count = 1;
            foreach (var ep in source.Description.Endpoints)
            {
                var epr = "Endpoint " + count.ToString() + " : " + ep.ListenUri;
                Console.WriteLine(epr);
                for (int i = 0; i < epr.Length; i++)
                {
                    Console.Write("=");
                }
                Console.WriteLine();
                foreach (var be in ep.Binding.CreateBindingElements())
                    Console.WriteLine(be.ToString());
                Console.WriteLine();
                count++;
            }
            Console.ForegroundColor = orignal;
            Console.WriteLine();
        }

        public static void WriteServiceBahviors(this ServiceHostBase source)
        {
            var orignal = Console.ForegroundColor;
            Console.ForegroundColor = ConsoleColor.Green;

            foreach (var bv in source.Description.Behaviors)
            {
                Console.WriteLine(bv.ToString());
            }

            Console.ForegroundColor = orignal;

        }


        public static void LogUnknownMessages(this ServiceHostBase source)
        {
            source.UnknownMessageReceived += delegate(object sender, UnknownMessageReceivedEventArgs e)
            {

                var orignal = Console.ForegroundColor;
                Console.ForegroundColor = ConsoleColor.Red;

                Console.WriteLine("Unknown message.");

                var writer = XmlDictionaryWriter.Create(Console.OpenStandardOutput(), new XmlWriterSettings { Indent = true });
                e.Message.WriteMessage(writer);
                writer.Flush();
                writer.Close();
                Console.WriteLine();

                Console.ForegroundColor = orignal;
            };
        }


        public static void EnableDebugTracking(this WorkflowServiceHost source)
        {
            source.WorkflowExtensions.Add(new DebuggingTrackingParticipant());
        }
    }


    public class DebuggingTrackingParticipant : TrackingParticipant
    {
        public DebuggingTrackingParticipant()
        {
            base.TrackingProfile = new TrackingProfile
            {
                Queries = 
                { 
                    new WorkflowInstanceQuery 
                    { 
                        States = { "*" } 
                    },
                   // new ActivityScheduledQuery{ ActivityName="*"}
                }
            };
        }
        protected override void Track(TrackingRecord record, TimeSpan timeout)
        {
            if (record is WorkflowInstanceUnhandledExceptionRecord)
            {

                var unRec = record as WorkflowInstanceUnhandledExceptionRecord;
                Console.ForegroundColor = ConsoleColor.Red;
                Console.WriteLine("Unhandled exception: " + unRec.UnhandledException.ToString());
                Console.ResetColor();
            }
            else if (record is WorkflowInstanceAbortedRecord)
            {
                Console.ForegroundColor = ConsoleColor.Red;
                Console.WriteLine("[*TR*] Workflow aborted. Reason = {0}", ((WorkflowInstanceAbortedRecord)record).Reason);
                Console.ResetColor();
            }
            else if (record is WorkflowInstanceRecord)
            {
                var instRecord = record as
                    WorkflowInstanceRecord;
                Console.WriteLine("[*TR*] Instance {0} state changed to :{1}" ,instRecord.InstanceId, instRecord.State);
            }
            else Console.WriteLine(record.GetType());
        }
    }
}
