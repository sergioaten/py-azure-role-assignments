import csv
import sys
import json
import argparse
import requests
import subprocess
import urllib.parse
from texttable import Texttable
from flatten_json import flatten


def get_access_token(resource, subscription=None):
    """
    Retrieves an access token for the specified resource.

    Args:
        resource (str): The resource for which to retrieve the access token.
        subscription (str, optional): The subscription ID. Defaults to None.

    Returns:
        str: The access token for the specified resource, or None if an error occurred.
    """
    command = f"az account get-access-token --query accessToken --resource {resource}"
    if subscription:
        command += f" --subscription {subscription}"
    command += " -o tsv"
    try:
        return subprocess.check_output(command, shell=True).decode().strip()
    except subprocess.CalledProcessError as e:
        print(f"Error retrieving access token: {e}")
        return None


def get_subs_from_tenant(access_token, subscription_id=None):
    """
    Retrieves subscription information from Azure Management API.

    Args:
        access_token (str): The access token for authentication.
        subscription_id (str, optional): The ID of the specific subscription to retrieve.
            If not provided, retrieves information for all subscriptions.

    Returns:
        list: A list of subscription information in JSON format.

    Raises:
        Exception: If there is an error retrieving the subscription information.

    """
    try:
        if subscription_id:
            uri = f"https://management.azure.com/subscriptions/{subscription_id}?api-version=2022-12-01"
            response = requests.get(
                uri,
                headers={"Authorization": f"Bearer {access_token}"}
            )
            return [response.json()]
        else:
            response = requests.get(
                "https://management.azure.com/subscriptions?api-version=2022-12-01",
                headers={"Authorization": f"Bearer {access_token}"}
            )
            return sorted(response.json()["value"], key=lambda x: x["displayName"])
    except Exception as e:
        print(f"Error retrieving subscription information: {e}")
        return []


def get_role_assignments(access_token, sub,  principal_id):
    """
    Retrieves the role assignments for a given principal ID in Azure.

    Args:
        access_token (str): The access token for authentication.
        sub (str): The subscription ID.
        principal_id (str): The ID of the principal.

    Returns:
        list: A list of role assignments.

    Raises:
        Exception: If there is an error retrieving the role assignments.
    """
    try:
        uri = f"https://management.azure.com/subscriptions/{sub}/providers/Microsoft.Authorization/roleAssignments?%24filter=assignedTo('{principal_id}')&api-version=2022-04-01"
        return requests.get(uri, headers={"Authorization": f"Bearer {access_token}"}).json()["value"]
    except Exception as e:
        print(f"Error retrieving role assignments: {e}")
        return []


def get_role_definition(access_token, sub, role_id):
    """
    Retrieves the role definition from Azure Active Directory.

    Args:
        access_token (str): The access token for authentication.
        sub (str): The subscription ID.
        role_id (str): The ID of the role definition.

    Returns:
        dict or None: The role definition as a dictionary if successful, None otherwise.
    """
    try:
        uri = f"https://management.azure.com/subscriptions/{sub}/providers/Microsoft.Authorization/roleDefinitions/{role_id}?api-version=2022-04-01"
        return requests.get(uri, headers={"Authorization": f"Bearer {access_token}"}).json()
    except Exception as e:
        print(f"Error retrieving role definition: {e}")
        return None


def get_principal_by_name(access_token, principal_name, principal_type):
    """
    Retrieves the ID of a principal (user, group, or service principal) by its name.

    Args:
        access_token (str): The access token used for authentication.
        principal_name (str): The name of the principal to retrieve.
        principal_type (str): The type of the principal. Can be 'user', 'group', or 'servicePrincipal'.

    Returns:
        str: The ID of the principal if found, None otherwise.
    """
    uri = "https://graph.microsoft.com/v1.0/"
    principal_name = urllib.parse.quote(principal_name)
    if principal_type == "user":
        endpoint = "users"
        filters = f"?$select=id,displayName&$filter=userPrincipalName eq '{principal_name}'"
    elif principal_type == "group":
        endpoint = "groups"
        filters = f"?$select=id,displayName&$filter=displayName eq '{principal_name}'"
    elif principal_type == "servicePrincipal":
        endpoint = "servicePrincipals"
        filters = f"?$select=id,displayName&$filter=displayName eq '{principal_name}'"

    try:
        uri = uri + endpoint + filters
        response = requests.get(
            uri,
            headers={"Authorization": f"Bearer {access_token}"}
        )
        return response.json()["value"][0]["id"]
    except Exception as e:
        if not response.json()["value"]:
            print(f"Principal not found: {principal_name}")
        print(f"Error retrieving principal: {e}")
        sys.exit(1)


def get_principal_data(access_token, principal_id):
    """
    Retrieves the principal data from Microsoft Graph API.

    Args:
        access_token (str): The access token for authentication.
        principal_id (str): The ID of the principal.

    Returns:
        dict: The principal data as a dictionary.

    Raises:
        Exception: If there is an error retrieving the principal data.

    """
    try:
        uri = f"https://graph.microsoft.com/v1.0/directoryObjects/getByIds"
        response = requests.post(
            uri,
            headers={"Authorization": f"Bearer {access_token}"},
            json={"ids": [principal_id]}
        )
        return response.json()["value"][0]
    except Exception as e:
        print(f"Error retrieving principal data: {e}")
        return None


def get_resource_type(resource_id):
    """
    Determines the type of resource based on the given resource ID.

    Args:
        resource_id (str): The resource ID to determine the type for.

    Returns:
        str: The type of resource. Possible values are:
            - "Management Group" if the resource ID represents a management group.
            - "Subscription" if the resource ID represents a subscription.
            - "Resource Group" if the resource ID represents a resource group.
            - "{provider}/{type1}" if the resource ID represents a generic resource type.
            - "{provider}/{type1}/{type2}" if the resource ID has parent resource.
            - "Invalid resource ID" if the resource ID is invalid.
            - "Unknown resource" if the resource ID does not match any known types.
    """
    if not resource_id == "/":
        parts = resource_id.split('/')
    else:
        return "Root Management Group"

    if len(parts) < 3:
        return "Invalid resource ID"

    if len(parts) > 3 and parts[2] == "Microsoft.Management" and parts[3] == "managementGroups":
        return "Management Group"

    if len(parts) > 9 and parts[3] == "resourceGroups" and parts[5] == "providers":
        provider = parts[6]
        type1 = parts[7]
        type2 = parts[9]
        return f"{provider}/{type1}/{type2}"
    if len(parts) > 7 and parts[3] == "resourceGroups" and parts[5] == "providers":
        provider = parts[6]
        type1 = parts[7]
        return f"{provider}/{type1}"

    if len(parts) == 5 and parts[3] == "resourceGroups":
        return "Resource Group"

    if len(parts) == 3:
        return "Subscription"

    return "Unknown resource"


def output_file(data, output_format):
    """
    Writes the given data to an output file in the specified format.

    Args:
        data: The data to be written to the output file.
        output_format: The format of the output file. Supported formats are "json" and "csv".
    """
    try:
        if output_format is None:
            return
        if output_format == "json":
            with open("output.json", "w") as f:
                json.dump(data, f, indent=4)
        elif output_format == "csv":
            if type(data) is dict:
                data = flatten(data)
            elif type(data) is list:
                data = [flatten(element) for element in data]
            else:
                print("Error: object type not supported.")
                return None

            with open("output.csv", "w") as file:
                csv_writer = csv.writer(file)
                csv_writer.writerow(data[0].keys())
                for item in data:
                    csv_writer.writerow(item.values())
    except Exception as e:
        print(f"Error writing to output file, make sure file is not open: {e}")


def main():
    """
    Azure Role Assignment Explorer

    This function retrieves role assignments for a given principal in Azure.
    It takes the following command line arguments:
    -n, --principal-name: Principal name to get role assignments for
                          user -> Email
                          group -> Group Name
                          servicePrincipal -> Service Principal Name
    -t, --principal-type: Principal type (choices: user, group, servicePrincipal)
    -s, --subscription-id: Subscription id to get role assignments for.
                           If not provided, all subscriptions will be checked.
    -o, --output: Output file format. It will create output.csv/json file in the current directory.
                  (choices: json, csv)
    """
    parser = argparse.ArgumentParser(
        description="Azure Role Assignment Explorer",
        formatter_class=argparse.RawTextHelpFormatter
    )
    parser.add_argument(
        "-n", "--principal-name", help="Principal name to get role assignments for\nuser -> Email\ngroup -> Group Name\nservicePrincipal -> Service Principal Name", required=True)
    parser.add_argument(
        "-t", "--principal-type", help="Principal type", choices=["user", "group", "servicePrincipal"], required=True)
    parser.add_argument(
        "-s", "--subscription-id", help="Subscription id to get role assignments for, if not provided, all subscriptions will be checked", required=False)
    parser.add_argument("-o", "--output", help="Output file format, will create output.csv/json file in the current directory",
                        choices=["json", "csv"], required=False, action="append")
    args = parser.parse_args()

    ARM_API = "https://management.azure.com"
    GRAPH_API = "https://graph.microsoft.com"

    arm_access_token = get_access_token(
        ARM_API, args.subscription_id)
    graph_access_token = get_access_token(
        GRAPH_API, args.subscription_id)

    if not arm_access_token or not graph_access_token:
        return

    subscriptions = get_subs_from_tenant(
        arm_access_token, args.subscription_id)
    principal_id = get_principal_by_name(
        graph_access_token, args.principal_name, args.principal_type)

    role_assignments_data = []
    for subscription in subscriptions:
        subscription_id = subscription["subscriptionId"]
        subscription_name = subscription["displayName"]
        print(f"Getting role assignments for {subscription_name} ...")
        role_assignments = get_role_assignments(
            arm_access_token, subscription_id, principal_id)

        for role_assignment in role_assignments:
            scope_id = role_assignment['properties']['scope']
            resource_type = get_resource_type(scope_id)
            if not scope_id == "/":
                resource_name = scope_id.split(
                    "/")[-1]
            else:
                resource_name = "/"

            role_id = role_assignment['properties']['roleDefinitionId'].split(
                "/")[-1]

            role_definition = get_role_definition(
                arm_access_token, subscription_id, role_id)

            role_assignment_principal_id = role_assignment['properties']['principalId']

            principal_data = get_principal_data(graph_access_token,
                                                role_assignment_principal_id)

            assigned_to = principal_data["displayName"] if principal_data[
                "@odata.type"] == "#microsoft.graph.user" or principal_data["@odata.type"] == "#microsoft.graph.group" else principal_data["displayName"]
            assigned_to_type = principal_data["@odata.type"].split(".")[-1]

            if resource_type == "Subscription":
                resource_name = subscription["displayName"]

            role_name = role_definition["properties"]["roleName"]
            role_condition = role_assignment["properties"]["condition"]

            data = {
                "subscriptionName": subscription_name,
                "subscriptionId": subscription_id,
                "roleName": role_name,
                "resourceType": resource_type,
                "resourceName": resource_name,
                "assignetToType": assigned_to_type,
                "assignedTo": assigned_to,
                "roleCondition": role_condition if role_condition is not None else "None"
            }

            role_assignments_data.append(data)

    data = [["Subscription Name", "Role Name", "Resource Type",
             "Name", "Assigned To Type", "Assigned To", "Condition"]]

    resource_type_order = {"Root Management Group": 1, "Management Group": 2,
                           "Subscription": 3, "Resource Group": 4}

    role_assignments_data = sorted(
        role_assignments_data,
        key=lambda x: (x["subscriptionName"],
                       resource_type_order.get(x["resourceType"], 5),
                       x["resourceType"],
                       x["resourceName"],
                       x["roleName"],
                       x["assignedTo"]))

    for roleassignment in role_assignments_data:
        data.append([
            roleassignment["subscriptionName"],
            roleassignment["roleName"],
            roleassignment["resourceType"],
            roleassignment["resourceName"],
            roleassignment["assignetToType"],
            roleassignment["assignedTo"],
            roleassignment["roleCondition"]
        ])

    col_widths = [max(len(str(x)) for x in col) for col in zip(*data)]

    table = Texttable()
    table.set_cols_width(col_widths)

    for row in data:
        table.add_row(row)

    print(table.draw())

    if args.output:
        for arg in args.output:
            output_file(role_assignments_data, arg)


if __name__ == "__main__":
    main()
