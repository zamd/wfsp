﻿//------------------------------------------------------------------------------
// <auto-generated>
//     This code was generated by a tool.
//     Runtime Version:4.0.30319.18033
//
//     Changes to this file may cause incorrect behavior and will be lost if
//     the code is regenerated.
// </auto-generated>
//------------------------------------------------------------------------------

namespace TestWorkflowService.BackendServiceReference {
    
    
    [System.CodeDom.Compiler.GeneratedCodeAttribute("System.ServiceModel", "4.0.0.0")]
    [System.ServiceModel.ServiceContractAttribute(ConfigurationName="BackendServiceReference.ITransformerService")]
    public interface ITransformerService {
        
        [System.ServiceModel.OperationContractAttribute(Action="http://tempuri.org/ITransformerService/Transform", ReplyAction="http://tempuri.org/ITransformerService/TransformResponse")]
        TestWorkflowService.BackendServiceReference.TransformResponse Transform(TestWorkflowService.BackendServiceReference.TransformRequest request);
    }
    
    [System.Diagnostics.DebuggerStepThroughAttribute()]
    [System.CodeDom.Compiler.GeneratedCodeAttribute("System.ServiceModel", "4.0.0.0")]
    [System.ServiceModel.MessageContractAttribute(WrapperName="Transform", WrapperNamespace="http://tempuri.org/", IsWrapped=true)]
    public partial class TransformRequest {
        
        [System.ServiceModel.MessageBodyMemberAttribute(Namespace="http://tempuri.org/", Order=0)]
        public string input;
        
        public TransformRequest() {
        }
        
        public TransformRequest(string input) {
            this.input = input;
        }
    }
    
    [System.Diagnostics.DebuggerStepThroughAttribute()]
    [System.CodeDom.Compiler.GeneratedCodeAttribute("System.ServiceModel", "4.0.0.0")]
    [System.ServiceModel.MessageContractAttribute(WrapperName="TransformResponse", WrapperNamespace="http://tempuri.org/", IsWrapped=true)]
    public partial class TransformResponse {
        
        [System.ServiceModel.MessageBodyMemberAttribute(Namespace="http://tempuri.org/", Order=0)]
        public string TransformResult;
        
        public TransformResponse() {
        }
        
        public TransformResponse(string TransformResult) {
            this.TransformResult = TransformResult;
        }
    }
}
