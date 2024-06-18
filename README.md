# Azure Sentinel Bulk Enable Rules

This allows you to bulk enable a chunk of Content Hub Analytics temapltes.

Basically the python version of this https://charbelnemnom.com/set-microsoft-sentinel-analytics-rules-at-scale/


### Authentication

For auth i used VSCode and the Azure powershell command.
    Connect-AzAccount

Then ran the script.

I had to pip install a few bits you can run the script and see what your environment doesn't have 


In the script update the following section

# Example usage:
subscription_id = "XXX"
resource_group_name = "XXX"
workspace_name = "XXX"
solution_name = "XXX"

Solution name should be the Source name of the rules installed from Content Hub e.g. 'Network Session Essentials'
