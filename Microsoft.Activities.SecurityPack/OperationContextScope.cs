using System;
using System.Activities;
using System.ComponentModel;
using System.Drawing;
using System.Runtime.Serialization;
using System.ServiceModel;
using System.ServiceModel.Activities;
using System.Windows.Markup;
using Microsoft.Activities.SecurityPack.Designers;
using Microsoft.Activities.SecurityPack.ToolboxIcons;

namespace Microsoft.Activities.SecurityPack
{
    [Designer(typeof(OperationContextScopeDesigner))]
    [ToolboxBitmap(typeof(IconMoniker), "OperationScope")]
    [ContentProperty("Body")]
    public sealed class OperationContextScope : NativeActivity
    {
        public Activity Body { get; set; }
        protected override void Execute(NativeActivityContext context)
        {
            if (this.Body != null)
            {                                                                       
                context.Properties.Add(OperationContextScopeProperty.Name,
                    new OperationContextScopeProperty()); 
                context.ScheduleActivity(this.Body);
            }
        }
    }

    [DataContract]
    internal class OperationContextScopeProperty: IReceiveMessageCallback, ISendMessageCallback, IExecutionProperty
    {
        private OperationContext _current;
        private OperationContext _orignal;

        public static readonly string Name = typeof(OperationContextScopeProperty).FullName;

        public void OnReceiveMessage(OperationContext operationContext, ExecutionProperties activityExecutionProperties)
        {
            _current = operationContext;
            operationContext.OperationCompleted += delegate(object sender, EventArgs e)
            {
                _current = null;
            };
        }

        public void CleanupWorkflowThread()
        {
            OperationContext.Current = _orignal;
        }

        public void SetupWorkflowThread()
        {
            _orignal = OperationContext.Current;
            OperationContext.Current = _current;
        }

        public void OnSendMessage(OperationContext operationContext)
        {
            _current = operationContext;
            operationContext.OperationCompleted += delegate(object sender, EventArgs e)
            {
                _current = null;
            };
        }
    }
}
