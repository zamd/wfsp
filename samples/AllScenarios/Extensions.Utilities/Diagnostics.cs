using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Diagnostics;

namespace Extensions.Utilities
{

    public static class Diagnostics
    {
        private static TraceSource trace;
        static Diagnostics()
        {
            trace = new TraceSource("WorkflowSecurityPack",SourceLevels.All);
            trace.Listeners.Clear();
            trace.Listeners.Add(new ConsoleTraceListener() );
        }
        public static TraceSource Trace
        {
            get
            {
                return trace;
            }
        }

        public static void TraceWarning(this TraceSource source, string message)
        {
            source.TraceEvent(TraceEventType.Warning, 0, message, null);
        }

        public static void TraceWarning(this TraceSource source, string format, params object[] args)
        {
            source.TraceEvent(TraceEventType.Warning, 0, format,  args);
        }

        public static void TraceError(this TraceSource source, string message)
        {
            source.TraceEvent(TraceEventType.Error, 0, message, null);
        }

        public static void TraceError(this TraceSource source, string format, params object[] args)
        {
            source.TraceEvent(TraceEventType.Error, 0, format, args);
        }

    }
}
