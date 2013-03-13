using System;
using System.Activities.Tracking;
using System.Collections.Generic;

namespace Microsoft.Activities.SecurityPack
{
    public class AcquiredSamlTokenRecord:CustomTrackingRecord
    {
        public AcquiredSamlTokenRecord(Uri appliesTo, DateTime? expiry):base("AcquiredSamlTokenRecord")
        {
            this.Data["appliesTo"] = appliesTo;
            if (expiry.HasValue)
                this.Data["ExpiresAt"] = expiry;
        }
    }
    public class PrincipalPermissionDemandRecord:CustomTrackingRecord
    {
        public PrincipalPermissionDemandRecord(string name, string role)
            : base("PrincipalPermissionDemandRecord")
        {
            this.Data["PrincipalPermissionName"] = name;
            this.Data["PrincipalPermissionRole"] = role;
        }
    }


    public class EnlistedTokensRecord : CustomTrackingRecord
    {
        public EnlistedTokensRecord(IList<string> flowTokens, string actAsToken)
            : base("PrincipalPermissionDemandRecord")
        {
            this.Data["FlowTokens"] = flowTokens;
            this.Data["ActAsToken"] = actAsToken;
        }
    }
    
}
