using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Data;
using System.Windows.Documents;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using System.Windows.Navigation;
using System.Windows.Shapes;
using System.IdentityModel.Tokens;
using System.Activities;

namespace Microsoft.Activities.SecurityPack.Designers
{
    // Interaction logic for InitializeActAsTokenDesigner.xaml
    public partial class InitializeActAsTokenDesigner
    {
        public InitializeActAsTokenDesigner()
        {
            InitializeComponent();
        }
        protected override void OnModelItemChanged(object newItem)
        {
            if (this.ModelItem.Properties["Initializer"].Value == null)
            {
                this.ModelItem.Properties["Initializer"].SetValue(
                    new ActivityFunc<SecurityToken>
                    {
                    }
                    );

            }
            base.OnModelItemChanged(newItem);
        }
    }
}
