using System;
using System.Activities;
using System.ServiceModel.Channels;

namespace Microsoft.Activities.SecurityPack
{
    public sealed class DumpTokenHandle : CodeActivity
    {
        public InArgument<SecurityTokenHandle> TokenHandle { get; set; }

        protected override void CacheMetadata(CodeActivityMetadata metadata)
        {
            base.CacheMetadata(metadata);
            if (this.TokenHandle == null)
                metadata.AddValidationError(string.Format("TokenHandle property must be set on {0}.", this.DisplayName));
        }
        protected override void Execute(CodeActivityContext context)
        {
            Console.ForegroundColor = ConsoleColor.Green;

            Console.WriteLine("Dumping token handle.");
            Console.WriteLine("<=====================\n");
            Console.WriteLine("Flow Tokens: ");
            Console.WriteLine("------------");
            var handle = this.TokenHandle.Get(context);
            foreach(var token in handle.EnlistedTokens)
                Console.WriteLine(token);

            Console.WriteLine();
            Console.WriteLine("Act As Token: ");
            Console.WriteLine("------------");
            Console.WriteLine(handle.ActAsToken);
            Console.WriteLine("\n====================/>");

            Console.ResetColor();
        }
    }

    internal sealed class NoOp : CodeActivity
    {
        protected override void Execute(CodeActivityContext context)
        {
            
        }
    }

    internal class EchoMessage : CodeActivity<Message>
    {
        public InArgument<Message> Input { get; set; }
        protected override Message Execute(CodeActivityContext context)
        {
            var msg = this.Input.Get(context);
            return msg;
        }
    }
}
