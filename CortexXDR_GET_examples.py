import requests, os
from dotenv import load_dotenv
import pandas as pd
import dash
from dash import dcc
from dash import html
import plotly.express as px
from dash import dash_table

#GET data from Cortex XDR using the API key as "Viewer" role.
#Set API Security Level to "Standard".
#Documentation https://docs-cortex.paloaltonetworks.com/r/Cortex-XDR-REST-API

def cortexCheck(api, id, fqdn, url_path):
    headers = {
        "x-xdr-auth-id": str(id), # Cortex API KEY ID
        "Authorization": api # Cortex API KEY
    }
    parameters = { "request_data": { } }
    res = requests.post(url=f'https://api-{fqdn}.xdr.us.paloaltonetworks.com/public_api{url_path}', 
						headers=headers,
						json=parameters)
    cortex = res.json()
    return cortex

def getData(api_key, api_id, api_fqdn):
    api_endpoint_list = {
    'get_versions': '/v1/distributions/get_versions',
    'get_endpoint': '/v1/endpoints/get_endpoint',
    'get_endpoints': '/v1/endpoints/get_endpoints',
    'get_violations': '/v1/device_control/get_violations',
    'get_incidents': '/v1/incidents/get_incidents',
    'get_alerts': '/v1/alerts/get_alerts/',
    'get_alerts_multi_events': '/v2/alerts/get_alerts_multi_events',
    'healthcheck': '/v1/healthcheck',
    'get_tenant_info': '/v1/system/get_tenant_info',
    'get_risky_hosts': '/v1/get_risky_hosts',
    'get_risky_users': '/v1/get_risky_users',
    'get_users': '/v1/rbac/get_users',
    'get_quota': '/v1/xql/get_quota',
    'agents_reports': '/v1/audits/agents_reports',
    'management_logs': '/v1/audits/management_logs'
    }
    allData = {}
    for id, name in enumerate(api_endpoint_list):
        data = cortexCheck(api_key,api_id,api_fqdn, api_endpoint_list[name])
        if name == "agents_reports" or name == "management_logs":
            allData[name] = pd.DataFrame(data['reply']['data'])
        elif name == "get_endpoint" or name == "get_endpoints":
            allData[name] = pd.DataFrame(data['reply'])
        elif name == "get_violations":
            allData[name] = pd.DataFrame(data['reply']['violations'])
        elif name == "get_incidents":
            allData[name] = df = pd.DataFrame(data['reply']['incidents'])
        elif name == "get_alerts" or name == "get_alerts_multi_events":
            allData[name] = pd.DataFrame(data['reply']['alerts'])
        elif name == "get_versions":
            allData[name] = pd.DataFrame(data['reply']['container'])
        elif name == "healthcheck":
            allData[name] = pd.DataFrame([data])
        elif name == "get_quota":
            allData[name] = pd.DataFrame([data['reply']])
        else:
            allData[name] = pd.DataFrame(data)
    return allData


def main():
    api_key = os.getenv(f"api_key")
    api_id = os.getenv(f"api_id")
    api_fqdn = os.getenv(f"api_fqdn")
    # Importa os dados em datadrame
    df = getData(api_key, api_id, api_fqdn)
    # Criando o aplicativo Dash
    app = dash.Dash(__name__)
    
    # Layout da aplicação
    app.layout = html.Div([
        html.Div([
            dash_table.DataTable(
            id='tabela',  # Definindo o nome da coluna como 'Valores'
            data=df['get_versions'].to_dict('records'),
            columns=[{'name': 'Windows versions', 'id': '0'}],
            style_table={'height': '150px', 'width': '150px'},
            style_header={'backgroundColor': 'lightgrey', 'fontWeight': 'bold'},
            style_cell={'textAlign': 'center'}
            )
        ])
    ])

    app.run_server(debug=True)

if __name__ == "__main__":
    main()

"""
#Endpoint Management
#Get a list of all the agent versions to use for creating a distribution list.
#Required license: Cortex XDR Prevent or Cortex XDR Pro per Endpoint
get_distributions_version = "/v1/distributions/get_versions"
data_distributions_version = cortexCheck(api_key,api_id,api_fqdn, get_distributions_version)
df = pd.DataFrame(data_distributions_version['reply']['container'])

#Endpoint Management
#Gets a list of endpoints. - The response is concatenated using AND condition (OR is not supported). 
#The maximum result set size is 100. - Offset is the zero-based number of endpoints from the start of the result set.
#Required license: Cortex XDR Prevent or Cortex XDR Pro per Endpoint
get_endpoint = "/v1/endpoints/get_endpoint"
data_endpoint = cortexCheck(api_key,api_id,api_fqdn, get_endpoint)
data_endpoint = pd.DataFrame(data_endpoint['reply'])
print(data_endpoint)
input()

#Endpoint Management
#Gets a list of all of your endpoints. The response is concatenated using AND condition (OR is not supported).
#Required license: Cortex XDR Prevent or Cortex XDR Pro per Endpoint
get_endpoints = "/v1/endpoints/get_endpoints"
data_endpoints = cortexCheck(api_key,api_id,api_fqdn, get_endpoints)
data_endpoints = pd.DataFrame(data_endpoints['reply'])
print(data_endpoints)
input()

#Endpoint Management
#Gets a list of device control violations. You can retrieve up to 100 violations.
#Required license: Cortex XDR Prevent or Cortex XDR Pro per Endpoint
get_violations = "/v1/device_control/get_violations"
data_violations = cortexCheck(api_key,api_id,api_fqdn, get_violations)
data_violations = pd.DataFrame(data_violations['reply']['violations'])
print(data_violations)
input()

#Incident Management
#Get a list of incidents filtered by a list of incident IDs, modification time, or creation time.
#The response is concatenated using AND condition (OR is not supported). - The maximum result set size is >100.
#Offset is the zero-based number of incidents from the start of the result set.
#Required license: Cortex XDR Prevent, Cortex XDR Pro per Endpoint, or Cortex XDR Pro per GB
get_incidents = "/v1/incidents/get_incidents"
data_incidents = cortexCheck(api_key,api_id,api_fqdn, get_incidents)
data_incidents = pd.DataFrame(data_incidents['reply']['incidents'])
print(data_incidents)
input()

#Incident Management
#Get a list of alerts. - Response is concatenated using AND condition (OR is not supported). 
#Maximum result set size is 100. - Offset is the zero-based number of alerts from the start of the result set.
#Required license: Cortex XDR Prevent, Cortex XDR Pro per Endpoint, or Cortex XDR Pro per GB
get_alerts = "/v1/alerts/get_alerts/"
data_alerts = cortexCheck(api_key,api_id,api_fqdn, get_alerts)
data_alerts = pd.DataFrame(data_alerts['reply']['alerts'])
print(data_alerts)
input()

#Incident Management
#Get a list of alerts with multiple events. - The response is concatenated using AND condition (OR is not supported). 
#The maximum result set size is 100. - Offset is the zero-based number of alerts from the start of the result set.
#Required license: Cortex XDR Prevent, Cortex XDR Pro per Endpoint, or Cortex XDR Pro per GB
get_alerts_multi_events = "/v2/alerts/get_alerts_multi_events"
data_alerts_multi_events = cortexCheck(api_key,api_id,api_fqdn, get_alerts_multi_events)
data_alerts_multi_events = pd.DataFrame(data_alerts_multi_events['reply']['alerts'])
print(data_alerts_multi_events)
input()

#Script Execution
#Get a list of scripts available in the scripts library.
#Required licence: Cortex XDR Pro per Endpoint or Cortex XDR Pro per GB
get_scripts = "/v1/scripts/get_scripts"
data_scripts = cortexCheck(api_key,api_id,api_fqdn, get_scripts)
data_scripts = pd.DataFrame(data_scripts)
print(data_scripts)
input()

#System Management
#Perform a health check of your Cortex XDR environment. Return the condition of your Cortex environment.
#Required license: Cortex XDR Prevent, Cortex XDR Pro per Endpoint, or Cortex XDR Pro per GB
get_healthcheck = "/v1/healthcheck"
data_healthcheck = cortexCheck(api_key,api_id,api_fqdn, get_healthcheck)
data_healthcheck = pd.DataFrame([data_healthcheck])
print(data_healthcheck)
input()

#System Management
#Get your tenant license information. Return list of available licenses, number of devices, and purchased add-ons on your tenant.
#Required license: Cortex XDR Prevent, Cortex XDR Pro per Endpoint, or Cortex XDR Pro per GB
get_tenant_info = "/v1/system/get_tenant_info"
data_tenant_info = cortexCheck(api_key,api_id,api_fqdn, get_tenant_info)
data_tenant_info = pd.DataFrame(data_tenant_info)
print(data_tenant_info)
input()

#System Management
#Retrieve the risk score of a specific user or endpoint in your environment, along with the reason for the score.
#Required license: Identity Threat Module -> An add-on license available for purchase on top of either the Cortex XDR Pro license
get_risky_hosts = "/v1/get_risky_hosts"
data_risky_hosts = cortexCheck(api_key,api_id,api_fqdn, get_risky_hosts)
data_risky_hosts = pd.DataFrame(data_risky_hosts)
print(data_risky_hosts)
input()

#System Management
#Retrieve a list of users with the highest risk score in your environment along with the reason affecting each score.
#Required license: Identity Threat Module -> An add-on license available for purchase on top of either the Cortex XDR Pro license
get_risky_users = "/v1/get_risky_users"
data_risky_users = cortexCheck(api_key,api_id,api_fqdn, get_risky_users)
data_risky_users = pd.DataFrame(data_risky_users)
print(data_risky_users)
input()

#System Management
#Retrieve a list of the current users in your environment.
#Required license: Cortex XDR Pro per Endpoint, Cortex XDR Pro, or Cortex XDR Pro per GB.
#Error: Insufficient permissions for api key -> Set "Instance Administrator" role.
get_users = "/v1/rbac/get_users"
data_users = cortexCheck(api_key,api_id,api_fqdn, get_users)
data_users = pd.DataFrame(data_users)
print(data_users)
input()

#XQL Query
#Retrieve the amount of query quota available and used.
#Required license: Cortex XDR Pro per Endpoint or Cortex XDR Pro per GB
get_xql_quota = "/v1/xql/get_quota"
data_xql_quota = cortexCheck(api_key,api_id,api_fqdn, get_xql_quota)
data_xql_quota = pd.DataFrame([data_xql_quota['reply']])
print(data_xql_quota)
input()

#Audit Log
#Get agent event reports. - Response is concatenated using AND condion (OR is not supported).
#Maximum result set size is 100. - Offset is the zero-based number of incidents from the start of the result set.
#Required license: Cortex XDR Prevent, Cortex XDR Pro per Endpoint, or Cortex XDR Pro per GB
get_agent_report = "/v1/audits/agents_reports"
data_agent_report = cortexCheck(api_key,api_id,api_fqdn, get_agent_report)
data_agent_report = pd.DataFrame(data_agent_report['reply']['data'])
print(data_agent_report)
input()

#Audit Log
#Get audit management logs. - Response is concatenated using AND condition (OR is not supported).
#Maximum result set size is 100. - Offset is the zero-based number of incidents from the start of the result set.
#Required license: Cortex XDR Prevent, Cortex XDR Pro per Endpoint, or Cortex XDR Pro per GB
get_management_logs = "/v1/audits/management_logs"
data_management_logs = cortexCheck(api_key,api_id,api_fqdn, get_management_logs)
data_management_logs = pd.DataFrame(data_management_logs['reply']['data'])
print(data_management_logs)
input()
"""