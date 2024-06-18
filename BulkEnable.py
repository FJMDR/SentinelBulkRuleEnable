import json
from azure.identity import DefaultAzureCredential
import requests

def connect_to_azure(subscription_id, resource_group_name, workspace_name, solution_name, enable_rules):
    try:
        # Authenticate using DefaultAzureCredential which supports various authentication methods
        credential = DefaultAzureCredential()

        # Define Azure API version
        api_version = "2024-01-01-preview"

        # Obtain the token for Azure Management API
        token = credential.get_token("https://management.azure.com/.default").token

        headers = {
            'Authorization': f'Bearer {token}',
            'Content-Type': 'application/json'
        }

        # Get Content Product Packages
        content_uri = f"https://management.azure.com/subscriptions/{subscription_id}/resourceGroups/{resource_group_name}/providers/Microsoft.OperationalInsights/workspaces/{workspace_name}/providers/Microsoft.SecurityInsights/contentProductPackages?api-version={api_version}"
        print(f"Requesting content packages from: {content_uri}")
        content_response = requests.get(content_uri, headers=headers)
        print(f"Status Code: {content_response.status_code}, Response: {content_response.text}")

        if content_response.status_code == 404:
            print(f"Error: {content_response.status_code} - URL not found: {content_uri}")
            return

        content_response.raise_for_status()

        solutions = [s for s in content_response.json().get('value', []) if s.get('properties', {}).get('version')]
        solution = next((s for s in solutions if s['properties']['displayName'] == solution_name), None)
        if not solution:
            raise Exception(f"Solution Name: [{solution_name}] cannot be found. Please check the solution name and Install it from the Content Hub blade")

        # Get Content Templates
        content_uri = f"https://management.azure.com/subscriptions/{subscription_id}/resourceGroups/{resource_group_name}/providers/Microsoft.OperationalInsights/workspaces/{workspace_name}/providers/Microsoft.SecurityInsights/contentTemplates?api-version={api_version}"
        print(f"Requesting content templates from: {content_uri}")
        content_response = requests.get(content_uri, headers=headers)
        print(f"Status Code: {content_response.status_code}, Response: {content_response.text}")

        if content_response.status_code == 404:
            print(f"Error: {content_response.status_code} - URL not found: {content_uri}")
            return

        content_response.raise_for_status()

        content_templates = [t for t in content_response.json().get('value', []) if
                             t.get('properties', {}).get('packageId') == solution['properties']['contentId'] and t.get('properties', {}).get('contentKind') == 'AnalyticsRule']

        print(f"{len(content_templates)} Analytic Rules found for: [{solution_name}]")

        for content_template in content_templates:
            rule_name = content_template['name']
            rule_template_uri = f"https://management.azure.com/subscriptions/{subscription_id}/resourceGroups/{resource_group_name}/providers/Microsoft.OperationalInsights/workspaces/{workspace_name}/providers/Microsoft.SecurityInsights/contentTemplates/{rule_name}?api-version={api_version}"
            rule_response = requests.get(rule_template_uri, headers=headers)
            rule_response.raise_for_status()

            rule_properties = next((r['properties'] for r in rule_response.json().get('properties', {}).get('mainTemplate', {}).get('resources', []) if r.get('type') == 'Microsoft.OperationalInsights/workspaces/providers/metadata'), None)
            if rule_properties:
                rule_properties.pop('description', None)
                rule_properties.pop('parentId', None)

            rule = next(
                (r for r in rule_response.json().get('properties', {}).get('mainTemplate', {}).get('resources', []) if
                 r.get('type') == 'Microsoft.SecurityInsights/AlertRuleTemplates'), None)
            if rule:
                rule['properties']['alertRuleTemplateName'] = rule['name']
                rule['properties']['templateVersion'] = rule_response.json().get('properties', {}).get('version')
                if enable_rules:
                    rule['properties']['enabled'] = True

            rule_payload = json.dumps(rule, separators=(',', ':'))
            rule_uri = f"https://management.azure.com/subscriptions/{subscription_id}/resourceGroups/{resource_group_name}/providers/Microsoft.OperationalInsights/workspaces/{workspace_name}/providers/Microsoft.SecurityInsights/alertRules/{rule['name']}?api-version={api_version}"

            try:
                rule_result = requests.put(rule_uri, headers=headers, data=rule_payload)
                print(f"PUT {rule_uri}")
                print(f"Payload: {rule_payload}")
                print(f"Response Status Code: {rule_result.status_code}")
                print(f"Response: {rule_result.text}")
                
                rule_result.raise_for_status()
                if rule_result.status_code not in [200, 201]:
                    raise Exception(f"Error when enabling Analytics rule: {rule['properties']['displayName']}")

                if enable_rules:
                    print(f"Creating and Enabling Analytic rule: {rule['properties']['displayName']}")
                else:
                    print(f"Creating Analytic rule: {rule['properties']['displayName']}")

                rule_result = rule_result.json()
                rule_properties['parentId'] = rule_result['id']

                # Correct the metadata type to Microsoft.SecurityInsights/metadata
                metadata_payload = {
                    "properties": rule_properties
                }
                metadata_payload = json.dumps(metadata_payload, separators=(',', ':'))

                metadata_uri = f"https://management.azure.com/subscriptions/{subscription_id}/resourceGroups/{resource_group_name}/providers/Microsoft.OperationalInsights/workspaces/{workspace_name}/providers/Microsoft.SecurityInsights/metadata/analyticsrule-{rule['name']}?api-version={api_version}"

                result_metadata = requests.put(metadata_uri, headers=headers, data=metadata_payload)
                print(f"PUT {metadata_uri}")
                print(f"Metadata Payload: {metadata_payload}")
                print(f"Response Status Code: {result_metadata.status_code}")
                print(f"Response: {result_metadata.text}")
                
                result_metadata.raise_for_status()
                if result_metadata.status_code not in [200, 201]:
                    raise Exception(f"Error when updating Metadata for Analytic rule: {rule['properties']['displayName']}")

                print(f"Updating Metadata for Analytic rule: {rule['properties']['displayName']}")

            except Exception as e:
                print(f"Error: {e}")

    except Exception as e:
        print(f"Error: {e}")

# Example usage:
subscription_id = "XXX"
resource_group_name = "XXX"
workspace_name = "XXX"
solution_name = "XXX"
enable_rules = True  # Set to True or False based on your requirements

connect_to_azure(subscription_id, resource_group_name, workspace_name, solution_name, enable_rules)
