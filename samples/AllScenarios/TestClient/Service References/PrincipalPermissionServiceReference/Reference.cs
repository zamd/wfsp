﻿//------------------------------------------------------------------------------
// <auto-generated>
//     This code was generated by a tool.
//     Runtime Version:4.0.30319.18033
//
//     Changes to this file may cause incorrect behavior and will be lost if
//     the code is regenerated.
// </auto-generated>
//------------------------------------------------------------------------------

namespace TestClient.PrincipalPermissionServiceReference {
    
    
    [System.CodeDom.Compiler.GeneratedCodeAttribute("System.ServiceModel", "4.0.0.0")]
    [System.ServiceModel.ServiceContractAttribute(ConfigurationName="PrincipalPermissionServiceReference.IAuctionService")]
    public interface IAuctionService {
        
        [System.ServiceModel.OperationContractAttribute(Action="http://tempuri.org/IAuctionService/PerformPrivilegedOp", ReplyAction="http://tempuri.org/IAuctionService/PerformPrivilegedOpResponse")]
        TestClient.PrincipalPermissionServiceReference.PerformPrivilegedOpResponse PerformPrivilegedOp(TestClient.PrincipalPermissionServiceReference.PerformPrivilegedOpRequest request);
        
        [System.ServiceModel.OperationContractAttribute(Action="http://tempuri.org/IAuctionService/PerformPrivilegedOp", ReplyAction="http://tempuri.org/IAuctionService/PerformPrivilegedOpResponse")]
        System.Threading.Tasks.Task<TestClient.PrincipalPermissionServiceReference.PerformPrivilegedOpResponse> PerformPrivilegedOpAsync(TestClient.PrincipalPermissionServiceReference.PerformPrivilegedOpRequest request);
    }
    
    [System.Diagnostics.DebuggerStepThroughAttribute()]
    [System.CodeDom.Compiler.GeneratedCodeAttribute("System.ServiceModel", "4.0.0.0")]
    [System.ServiceModel.MessageContractAttribute(IsWrapped=false)]
    public partial class PerformPrivilegedOpRequest {
        
        public PerformPrivilegedOpRequest() {
        }
    }
    
    [System.Diagnostics.DebuggerStepThroughAttribute()]
    [System.CodeDom.Compiler.GeneratedCodeAttribute("System.ServiceModel", "4.0.0.0")]
    [System.ServiceModel.MessageContractAttribute(IsWrapped=false)]
    public partial class PerformPrivilegedOpResponse {
        
        public PerformPrivilegedOpResponse() {
        }
    }
}