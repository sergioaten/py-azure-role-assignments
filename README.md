# Azure Role Assignment Explorer

This Python script enables Azure Administrators to explore role assignments for a given principal in Azure. It utilizes Azure Management API and Microsoft Graph API to retrieve role assignments, role definitions, and principal information. The script supports command-line arguments for specifying principal details, subscription ID, and output file format.

## Prerequisites
- Python 3.x
- `az` command-line tool installed and configured with appropriate permissions Azure subscription and principal details

## Installation
1. Clone or download the script from the repository.
2. Install the required Python packages using pip install -r requirements.txt

## Usage
1. Login to Azure using the `az login --tenant <tenant id or domain name>` command
2. Run the script using the following command
```
python main.py -n/--principal-name <Principal Name> -t/--principal-type <Principal Type> -s/--subscription [Subscription ID] -o/--output [Output Format]
```

## Command-line Arguments:
- `-n, --principal-name`: Principal name to get role assignments for
- `-t, --principal-type`: Principal type (choices: user, group, servicePrincipal).
  - user -> Search by UPN in principal-name argument.
  - group -> Search by Group Name in principal-name argument.
  - servicePrincipal -> Search by Service Principal Name in principal-name argument.
- `-s, --subscription-id`: (Optional) Subscription ID to get role assignments for. If not provided, role assignments for all subscriptions will be checked.
- `-o, --output`: (Optional) Output file format. It will create output.csv/json file in the current directory (choices: json, csv).

## Examples
Get role assignments for a user in a specific subscription and save the output in CSV format
```
python main.py -n example@example.com#EXT#@contoso.onmicrosoft.com -t user -s 00000000-0000-0000-0000-000000000000 -o csv
```
Get role assignments for a service principal in all subscriptions and save the output in CSV and JSON format
```
python main.py -n APP-TEST -t servicePrincipal -o csv -o json
```
Get role assignments for a group in all subscriptions
```
python main.py -n "AZ-ADMINS" -t group
```

## Output
The script generates an output table displaying role assignments for the specified principal within Azure subscriptions. Additionally, it saves the data in either JSON or CSV format based on the specified output format.

In the examples-output folder you can see an example of each output in JSON or CSV
