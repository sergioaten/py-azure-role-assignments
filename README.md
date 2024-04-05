# Azure Role Assignment Explorer

This Python script enables Azure Administrators to explore role assignments for a given principal in Azure. It utilizes Azure Management API and Microsoft Graph API to retrieve role assignments, role definitions, and principal information. The script supports command-line arguments for specifying principal details, subscription ID, and output file format.

## Prerequisites
- Python 3.x
- `az` command-line tool installed and configured with appropriate permissions Azure subscription and principal details

## Installation
1. Clone or download the script from the repository.
2. Install the required Python packages using pip install -r requirements.txt

## Usage
1. Login to Azure using the `az login` command
2. Run the script using the following command
```
python script_name.py -n/--principal-name <Principal Name> -t/--principal-type <Principal Type> -s/--subscription [Subscription ID] -o/--output [Output Format]
```

## Command-line Arguments:
`-n, --principal-name`: Principal name to get role assignments for (user -> Email, group -> Group Name, servicePrincipal -> Service Principal Name).
`-t, --principal-type`: Principal type (choices: user, group, servicePrincipal).
`-s, --subscription-id`: (Optional) Subscription ID to get role assignments for. If not provided, role assignments for all subscriptions will be checked.
`-o, --output`: (Optional) Output file format. It will create output.csv/json file in the current directory (choices: json, csv).

## Example
```
python script_name.py -n example@example.com -t user -s subscription_id -o json
```

## Output
The script generates an output table displaying role assignments for the specified principal within Azure subscriptions. Additionally, it saves the data in either JSON or CSV format based on the specified output format.
