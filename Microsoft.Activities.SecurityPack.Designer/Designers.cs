using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Windows.Data;
using System.Windows;
using System.Diagnostics;
using System.Activities.Presentation.Model;
using System.Activities;
using System.IdentityModel.Tokens;
using System.Windows.Media;

namespace Microsoft.Activities.SecurityPack.Designers
{
    public class GetSamlSecurityTokenDesigner : InitializeSamlSecurityTokenDesigner
    {
        public GetSamlSecurityTokenDesigner()
        {
            base.Icon = (DrawingBrush)base.FindResource("GetSamlToken");
        }
    }

    public class GetUserNameSecurityTokenDesigner : InitializeUserNameSecurityTokenDesigner
    {
        public GetUserNameSecurityTokenDesigner()
        {
            base.Icon = (DrawingBrush)base.FindResource("GetUserNameToken");
        }
    }
}
