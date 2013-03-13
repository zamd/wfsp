using System;
using System.Activities;
using System.Activities.Statements;
using System.Collections.Generic;
using System.IdentityModel.Tokens;
using System.Linq;
using System.ServiceModel;
using System.ServiceModel.Activities;
using Microsoft.Activities.SecurityPack;


namespace TestClient
{
    class Command
    {
        public string DisplayName;
        public Action Run;
        public char Option;
        public bool Break;
    }

    class Program
    {

        static IList<Command> GetCommandMap()
        {
            return new List<Command>
            {
                new Command{ DisplayName="Help", Option = 'H', Run = DisplayHelp},
                new Command{ DisplayName= "Clear Console", Option = 'C', Run = delegate{Console.Clear();DisplayHelp();}},

                new Command{ DisplayName="UserName Token Flow", Option = '1', Run = TestUserNameTokenFlow},
                new Command{ DisplayName="UserName Token Flow as a SecureConversation bootstrap token", Option = '2', Run = TestSecureConversationUserNameTokenFlow},
                new Command{ DisplayName="Get & Initialize Saml Token to an 'Ambiant Handle'", Option = '3', Run = TestInitializeSamlToken},
                new Command{ DisplayName="Get Saml Token 'Acting As' another identity", Option = '4', Run = TestActAsInSamlToken},
                new Command{ DisplayName="Get Saml Token & Invoke a Saml Token Secured Service - Distributed Auth", Option = '5', Run = TestDistributedAuth},
                new Command{ DisplayName="End to end delegation, Client -> Service -> Backend Service", Option = '6', Run = EndToEndDelegation},
                new Command{ DisplayName="Preserve Tokens across persistence episodes", Option = '7', Run = KickOffLongRunningService},

                new Command{ DisplayName="PrincipalPermission based authorization(*Fail mode*)", Option = '8', Run = TestPrincipalPermissionAuthorization},
                new Command{ DisplayName="Impersonating Receive Scope", Option = '9', Run = TestImpersonationScope},
                new Command{ DisplayName="ImpersonateToken Scope", Option = '0', Run = RunImpersonateTokenScope, Break=false },
            };
        }

        static void Main(string[] args)
        {
            DisplayHelp();
            RunCommandLoop(GetCommandMap());
        }

        private static void RunCommandLoop(IList<Command> commandMap)
        {
            bool @break = false;
            while(!@break)
            {
                var ch = Console.ReadKey();
                char option = char.ToUpper(ch.KeyChar);

                var cmd = commandMap.FirstOrDefault(t => t.Option == option);
                if (cmd != null)
                {
                    @break = cmd.Break;
                    Console.WriteLine("\n Executing {0}...", cmd.DisplayName);

                    try
                    {
                        cmd.Run();
                    }
                    catch (Exception exp)
                    {
                        Console.WriteLine("Command execution failed: Exception = {0}", exp.Message);
                        while (exp.InnerException != null)
                        {
                            Console.WriteLine("InnerException = {0}", exp.InnerException.Message);
                            exp = exp.InnerException;
                        }
                        DisplayHelp();
                    }
                }
            }
        }

        private static void DisplayHelp()
        {
            foreach (var item in GetCommandMap())
            {
                Console.WriteLine(" {0} = {1}", item.Option, item.DisplayName);
            }
            Console.WriteLine();
            Console.Write(" Please press a key to run the corresponding test > ");
        }


        private static void KickOffLongRunningService()
        {
            WorkflowInvoker.Invoke(
                new Send
                {
                    ServiceContractName = "ITokenPersist",
                    OperationName = "Start",
                    Endpoint = new System.ServiceModel.Endpoint { Binding = new BasicHttpBinding(), AddressUri = new Uri("http://localhost:8086/") }
                });
            Console.WriteLine("Operation started...");
        }

        private static void TestUserNameTokenFlow()
        {
            WorkflowInvoker.Invoke(new UserNameTokenFlow());

            Console.WriteLine("Test completed.");
        }

        private static void TestImpersonationScope()
        {
            WorkflowInvoker.Invoke(new TestImpersonation());

            Console.WriteLine("Test completed.");
        }

        private static void TestActAsInSamlToken()
        {
            var th = new Variable<SecurityTokenHandle>("th");
            //fixed for RC breaking changes.
            var appliesTo = new Variable<Uri>("appliesTo", context => new Uri("http://zamd.net"));

            var wf = new Sequence
            {
                Variables = { th, appliesTo },

                Activities = 
                {
                    new TokenFlowScope
                    {
                        TokenHandle = new InArgument<SecurityTokenHandle>(th),
                        Body = new Sequence
                        {
                            Activities = 
                            {
                                new InitializeActAsToken
                                {
                                    Initializer = new ActivityFunc<SecurityToken> { Handler = 
                                        new GetUserNameSecurityToken{ UserName="zamd", Password="p@ssw0rd1"}
                                    }
                                },
                                new InitializeSamlSecurityToken{ AppliesTo= new InArgument<Uri>(appliesTo), IssuerEndpointConfigurationName="stsEPR"},
                            }
                        }
                    },
                    new DumpTokenHandle{ TokenHandle=th}
                }
            };
            WorkflowInvoker.Invoke(wf);

            Console.WriteLine("Test completed.");
        }

        private static void TestInitializeSamlToken()
        {
            WorkflowInvoker.Invoke(new InitSamlTokenTest());
        }

        private static void TestGetSamlTokenTest()
        {
            var res =
                WorkflowInvoker.Invoke(new AcquireSamlToken());

            Console.WriteLine("Token  = {0}", res["samlToken"]);

        }

        private static void TestSecureConversationUserNameTokenFlow()
        {
            WorkflowInvoker.Invoke(new Send
            {
                OperationName = "Ping",
                ServiceContractName = "IPingService",
                Content = SendContent.Create(new Dictionary<string, InArgument>()),
                EndpointConfigurationName = "pingEprSecureConv"
            });
            Console.WriteLine("Test completed.");
        }

        private static void TestDistributedAuth()
        {
            WorkflowInvoker.Invoke(new AcquireSamlTokenAndCallService());
            Console.WriteLine("Test completed.");
        }

        private static void TestPrincipalPermissionAuthorization()
        {
            WorkflowInvoker.Invoke(new PrincipalPermissionAuthorization());
            Console.WriteLine("Test completed.");
        }

        private static void EndToEndDelegation()
        {
            WorkflowInvoker.Invoke(new IdentityDelegationTest());
            Console.WriteLine("Test completed.");
        }

        private static void RunImpersonateTokenScope()
        {
            WorkflowInvoker.Invoke(new TestImpersonateTokenScope());
            Console.WriteLine("Test completed.");
        }


    }
}
