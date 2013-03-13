using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.ServiceModel;
using System.Security.Cryptography.X509Certificates;
using System.ServiceModel.Security;
using System.ServiceModel.Description;
using System.Activities;
using System.ServiceModel.Activities;

namespace Extensions.Utilities
{

    public class Transform
    {
        public string Name { get; set; }
        private Action<ServiceHostBase> action;
        public Transform(Action<ServiceHostBase> action)
        {
            this.action = action;
        }
        public Transform(string name, Action<ServiceHostBase> action)
            : this(action)
        {
            this.Name = name;
        }
        public void Apply(ServiceHostBase host) { action(host); }
        public override string ToString()
        {
            return Name;
        }
    }

    public class ServiceHostManager
    {
        public static readonly Transform DebugTransform = new Transform("SetIncludeExceptionDetailInFaults", host =>
        {
            var debug = host.Description.Behaviors.Find<ServiceDebugBehavior>();
            if (debug == null)
            {
                debug = new ServiceDebugBehavior();
                host.Description.Behaviors.Add(debug);
            }
            debug.IncludeExceptionDetailInFaults = true;
        });

        public const string Prolog = "prologTransform";
        public const string Epilog = "epilogTransform";

        private int freePort;
        private IDictionary<ServiceHostBase, List<Transform>> hostTransformMap;

        public ServiceHostManager():this(8081)
        {
        }
        public ServiceHostManager(int startPort)
        {
            hostTransformMap
                = new Dictionary<ServiceHostBase, List<Transform>>();
            this.freePort =  startPort;
        }

        public ServiceHostBase RegisterActivity(Activity root, Uri httpBaseAddress)
        {
            if (httpBaseAddress == null)
                httpBaseAddress = new Uri(string.Format("http://localhost:{0}", freePort++));
            var wfsh = new WorkflowServiceHost(root, httpBaseAddress);

            wfsh.ConfigureMetadataViaHttpGet();
            wfsh.EnableDebugTracking();
            hostTransformMap[wfsh] = new List<Transform>();

            // default prolog & epilog for diagnostics...
            hostTransformMap[wfsh].Add(
                new Transform(Prolog,
                    host =>
                    {
                        Console.WriteLine("'{0}' Host.", wfsh.Activity.DisplayName);
                        Console.WriteLine("<========================");
                    }));

            hostTransformMap[wfsh].Add(
                new Transform(Epilog,
                    host =>
                    {
                        Console.WriteLine(host.WriteEndpoints());
                        Console.WriteLine("========================/>");
                    }));

            hostTransformMap[wfsh].Add(DebugTransform);

            return wfsh;
        }
        public ServiceHostBase RegisterActivity(Activity activity)
        {
            return RegisterActivity(activity, null);
        }

        public void AddTransform(ServiceHostBase host, Transform transform)
        {
            if (hostTransformMap[host] == null)
                hostTransformMap[host] = new List<Transform>();

            hostTransformMap[host].Add(transform);
        }

        public void AddTransform(ServiceHostBase host, Action<ServiceHostBase> transform)
        {
            AddTransform(host, new Transform(transform));
        }

        public ServiceHostBase RegisterService(Type serviceType, Uri httpBaseAddress)
        {
            if (httpBaseAddress == null)
                httpBaseAddress = new Uri(string.Format("http://localhost:{0}", freePort++));

            var sh = new ServiceHost(serviceType, httpBaseAddress);

            hostTransformMap[sh] = new List<Transform>();
            // default prolog & epilog transforms for diagnostics...
            hostTransformMap[sh].Add(
                new Transform(Prolog,
                    host =>
                    {
                        Console.WriteLine("'{0}' Host.", serviceType.FullName);
                        Console.WriteLine("<========================");
                    }));

            hostTransformMap[sh].Add(
                new Transform(Epilog,
                    host =>
                    {
                        Console.WriteLine(host.WriteEndpoints());
                        Console.WriteLine("========================/>");
                    }));
            hostTransformMap[sh].Add(DebugTransform);
            return sh;
        }

        public ServiceHostBase RegisterService(Type serviceType)
        {
            return RegisterService(serviceType, null);
        }

        public void RegisterHost(ServiceHostBase host)
        {
            hostTransformMap[host] = new List<Transform>();

            //Register default transforms...
            hostTransformMap[host].Add(
                new Transform(Epilog,
                    h =>
                    {
                        Console.WriteLine(host.WriteEndpoints());
                        Console.WriteLine("========================/>");
                    }));
            hostTransformMap[host].Add(DebugTransform);
        }

        public void Open()
        {
            foreach (var host in hostTransformMap.Keys)
            {
                var epilog = hostTransformMap[host].Where(t => t.Name == Epilog).First();
                hostTransformMap[host].Remove(epilog);

                foreach (var transform in hostTransformMap[host])
                    transform.Apply(host);
                host.Open();

                epilog.Apply(host);
            }
        }

        public void Close()
        {
            foreach (var host in hostTransformMap.Keys)
            {
                host.Close();
            }
        }
    }
}
