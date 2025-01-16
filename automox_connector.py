import json
import re
from typing import Any, Collection
from urllib.parse import quote, urlencode

import phantom.app as phantom
import requests
from bs4 import BeautifulSoup
from phantom.action_result import ActionResult
from phantom.base_connector import BaseConnector

from automox_consts import *


class RetVal(tuple):

    def __new__(cls, val1, val2=None):
        return tuple.__new__(RetVal, (val1, val2))


class AutomoxConnector(BaseConnector):

    def __init__(self):

        super(AutomoxConnector, self).__init__()

        self._state = None
        self._base_url = None

    def initialize(self):

        config = self.get_config()

        # Load the state in initialize, use it to store data
        # that needs to be accessed across actions
        self._state = self.load_state()

        self._base_url = AUTOMOX_CONSOLE_API_URL

        self._headers = {"Content-Type": "application/json", "Authorization": f"Bearer {config['ax_console_api_key']}"}

        self._page_limit = int(config.get("page_limit", 100))

        return phantom.APP_SUCCESS

    def _build_url(self, endpoint, path_params=None, query_params=None):
        """
        Constructs a full URL by replacing placeholders in the base endpoint and appending query parameters
        """

        # Replace path params
        if path_params:
            for key, value in path_params.items():
                safe_value = quote(str(value), safe="")
                placeholder = f"{{{key}}}"
                if placeholder in endpoint:
                    endpoint = endpoint.replace(placeholder, safe_value)
                else:
                    self.debug_print(f"Warning: Path param key '{key}' not found in endpoint.")

        # Filter out None or empty values from query parameters
        if query_params:
            query_params = {k: v for k, v in query_params.items() if v is not None and v != ""}

        # Append query params
        full_url = endpoint
        if query_params:
            query_string = urlencode(query_params)
            full_url = f"{endpoint}?{query_string}"

        self.debug_print(f"The full URL we're returning: {full_url}")
        return full_url

    def _process_empty_response(self, response, action_result):
        if response.status_code in [200, 204]:
            return RetVal(phantom.APP_SUCCESS, {})

        return RetVal(action_result.set_status(phantom.APP_ERROR, "Empty response and no information in the header"), None)

    def _process_html_response(self, response, action_result):
        status_code = response.status_code

        try:
            soup = BeautifulSoup(response.text, "html.parser")
            error_text = soup.text
            split_lines = error_text.split("\n")
            split_lines = [x.strip() for x in split_lines if x.strip()]
            error_text = "\n".join(split_lines)
        except:
            error_text = "Cannot parse error details"

        message = "Status Code: {0}. Data from server:\n{1}\n".format(status_code, error_text)

        message = message.replace("{", "{{").replace("}", "}}")
        return RetVal(action_result.set_status(phantom.APP_ERROR, message), None)

    def _process_json_response(self, r, action_result):
        try:
            resp_json = r.json()
        except Exception as e:
            return RetVal(action_result.set_status(phantom.APP_ERROR, "Unable to parse JSON response. Error: {0}".format(str(e))), None)

        if 200 <= r.status_code < 399:
            return RetVal(phantom.APP_SUCCESS, resp_json)

        message = "Error from server. Status Code: {0} Data from server: {1}".format(r.status_code, r.text.replace("{", "{{").replace("}", "}}"))

        return RetVal(action_result.set_status(phantom.APP_ERROR, message), None)

    def _process_response(self, r, action_result):
        if hasattr(action_result, "add_debug_data"):
            action_result.add_debug_data({"r_status_code": r.status_code})
            action_result.add_debug_data({"r_text": r.text})
            action_result.add_debug_data({"r_headers": r.headers})

        if "json" in r.headers.get("Content-Type", ""):
            return self._process_json_response(r, action_result)

        if "html" in r.headers.get("Content-Type", ""):
            return self._process_html_response(r, action_result)

        if not r.text:
            return self._process_empty_response(r, action_result)

        message = "Can't process response from server. Status Code: {0} Data from server: {1}".format(
            r.status_code, r.text.replace("{", "{{").replace("}", "}}")
        )

        return RetVal(action_result.set_status(phantom.APP_ERROR, message), None)

    def _make_rest_call(self, endpoint, action_result, method="get", **kwargs):

        config = self.get_config()

        resp_json = None

        try:
            request_func = getattr(requests, method)
        except AttributeError:
            return RetVal(action_result.set_status(phantom.APP_ERROR, "Invalid method: {0}".format(method)), resp_json)

        url = self._base_url + endpoint

        try:
            r = request_func(url, verify=config.get("verify_server_cert", False), **kwargs)
        except Exception as e:
            return RetVal(action_result.set_status(phantom.APP_ERROR, "Error Connecting to server. Details: {0}".format(str(e))), resp_json)

        return self._process_response(r, action_result)

    # Pagination support

    def _fetch_paginated_data(self, base_endpoint, path_params, query_params, action_result):
        pagination_params = self.first_page(query_params)
        all_items = []

        while True:
            endpoint = self._build_url(base_endpoint, path_params, pagination_params)
            ret_val, response = self._make_rest_call(endpoint, action_result, params=None, headers=self._headers)

            if phantom.is_fail(ret_val):
                return None, action_result.get_status()

            all_items.extend(response)

            if len(response) < self._page_limit:
                break

            self.next_page(pagination_params)

        return all_items, phantom.APP_SUCCESS

    def first_page(self, params=None) -> dict:
        if params is None:
            params = {}
        params.update({"limit": self._page_limit, "page": 0})
        return params

    @staticmethod
    def next_page(params: dict) -> None:
        params["page"] += 1

    @staticmethod
    def _is_value_or_number(value: Any) -> bool:
        """
        Check if value is not null or number to prevent 0 from being removed
        """
        if isinstance(value, (int, float)):
            return True
        elif value is not None:
            return True
        else:
            return False

    def remove_null_values(self, item: Collection):
        """
        Recursively remove null values from a dictionary or list
        """
        if isinstance(item, dict):
            return dict(
                (key, self.remove_null_values(value))
                for key, value in item.items()
                if self._is_value_or_number(value) and self._is_value_or_number(self.remove_null_values(value))
            )
        elif isinstance(item, list):
            return [
                self.remove_null_values(value)
                for value in item
                if self._is_value_or_number(value) and self._is_value_or_number(self.remove_null_values(value))
            ]
        else:
            return item

    def _handle_test_connectivity(self, param):
        action_result = self.add_action_result(ActionResult(dict(param)))

        endpoint = AUTOMOX_USERS_SELF_ENDPOINT
        self.save_progress("Connecting to endpoint")

        ret_val, response = self._make_rest_call(endpoint, action_result, params=None, headers=self._headers)

        if phantom.is_fail(ret_val):
            self.save_progress("Test Connectivity Failed.")

        self.save_progress("Test Connectivity Passed")
        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_run_worklet(self, param):
        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))

        action_result = self.add_action_result(ActionResult(dict(param)))

        base_endpoint = AUTOMOX_POLICY_RUN_ENDPOINT

        path_params = {"policy_id": param["policy_id"]}

        query_params = {"o": param.get("org_id")}

        endpoint = self._build_url(base_endpoint, path_params, query_params)

        # POST body
        server_id = param["server_id"]
        body = {"action": "remediateAll", "serverId": server_id}

        # make rest call
        ret_val, response = self._make_rest_call(
            endpoint,
            action_result,
            params=body,
            headers=self._headers,
            method="post",
        )

        if phantom.is_fail(ret_val):
            return action_result.get_status()

        action_result.add_data(response)

        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_list_policies(self, param):
        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))

        action_result = self.add_action_result(ActionResult(dict(param)))

        base_endpoint = AUTOMOX_POLICY_LIST_ENDPOINT
        path_params = None
        query_params = {"o": param.get("org_id")}

        all_policies, ret_val = self._fetch_paginated_data(base_endpoint, path_params, query_params, action_result)

        if phantom.is_fail(ret_val):
            return action_result.get_status()

        action_result.add_data(all_policies)

        summary = action_result.update_summary({})
        summary["total_policies"] = len(all_policies)

        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_list_devices(self, param):
        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))

        action_result = self.add_action_result(ActionResult(dict(param)))

        base_endpoint = AUTOMOX_DEVICE_LIST_ENDPOINT
        path_params = None
        query_params = {"o": param.get("org_id")}

        all_devices, ret_val = self._fetch_paginated_data(base_endpoint, path_params, query_params, action_result)

        if phantom.is_fail(ret_val):
            return action_result.get_status()

        action_result.add_data(all_devices)

        summary = action_result.update_summary({})
        summary["total_devices"] = len(all_devices)

        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_list_organizations(self, param):
        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))

        action_result = self.add_action_result(ActionResult(dict(param)))

        base_endpoint = AUTOMOX_ORGS_LIST_ENDPOINT
        path_params = None
        query_params = None

        all_orgs, ret_val = self._fetch_paginated_data(base_endpoint, path_params, query_params, action_result)

        if phantom.is_fail(ret_val):
            return action_result.get_status()

        action_result.add_data(all_orgs)

        summary = action_result.update_summary({})
        summary["total_orgs"] = len(all_orgs)

        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_get_device_software(self, param):
        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))

        action_result = self.add_action_result(ActionResult(dict(param)))

        base_endpoint = AUTOMOX_DEVICE_LIST_PACKAGES_ENDPOINT
        path_params = {"device_id": param["device_id"]}
        query_params = {"o": param.get("org_id")}

        all_software, ret_val = self._fetch_paginated_data(base_endpoint, path_params, query_params, action_result)

        if phantom.is_fail(ret_val):
            return action_result.get_status()

        action_result.add_data(all_software)

        summary = action_result.update_summary({})
        summary["num_of_packages"] = len(all_software)

        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_get_device(self, param):
        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))

        action_result = self.add_action_result(ActionResult(dict(param)))

        base_endpoint = AUTOMOX_DEVICE_LIST_SPECIFIC_ENDPOINT

        path_params = {"device_id": param["device_id"]}
        query_params = {"o": param.get("org_id")}

        endpoint = self._build_url(base_endpoint, path_params, query_params)

        ret_val, response = self._make_rest_call(endpoint, action_result, params=None, headers=self._headers)

        if phantom.is_fail(ret_val):
            return action_result.get_status()

        action_result.add_data(response)

        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_get_device_by_hostname(self, param):
        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))

        action_result = self.add_action_result(ActionResult(dict(param)))

        hostname = param["hostname"]
        org_id = param.get("org_id", "")

        device = self.find_device_by_attribute(org_id, ["name"], hostname)

        if not device:
            return action_result.set_status(phantom.APP_ERROR, f"Device with hostname {hostname} not found")

        action_result.add_data(device)

        return action_result.set_status(phantom.APP_SUCCESS)

    def find_device_by_attribute(self, org_id: int, attributes: list[str], value: str) -> dict:
        self.debug_print("Starting find_device_by_attribute")

        params = self.first_page({"o": org_id})
        self.debug_print(f"Params: {params}")

        action_result = ActionResult()

        while True:
            self.debug_print("Was true")
            ret_val, devices = self._make_rest_call(AUTOMOX_DEVICE_LIST_ENDPOINT, action_result, params=params, headers=self._headers)

            self.debug_print("Response from devices api:")
            self.debug_print(devices)

            if phantom.is_fail(ret_val):
                self.debug_print(f"Failed to get devices: {action_result.get_message()}")
                return {}

            for device in devices:
                self.debug_print(f"Device: {device}")
                for attr in attributes:
                    self.debug_print(f"Attribute: {attr}")
                    if isinstance(device.get(attr), str) and device[attr].casefold() == value.casefold():
                        return self.remove_null_values(device)
                    if isinstance(device.get(attr), list) and value.lower() in (v.lower() for v in device[attr]):
                        return self.remove_null_values(device)

            if len(devices) < params["limit"]:
                break

            self.next_page(params)

        self.debug_print(f"Device {value} not found")
        return {}

    def _handle_list_organization_users(self, param):
        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))

        action_result = self.add_action_result(ActionResult(dict(param)))

        base_endpoint = AUTOMOX_USERS_LIST_ENDPOINT
        path_params = None
        query_params = {"o": param.get("org_id")}

        all_org_users, ret_val = self._fetch_paginated_data(base_endpoint, path_params, query_params, action_result)

        if phantom.is_fail(ret_val):
            return action_result.get_status()

        action_result.add_data(all_org_users)

        summary = action_result.update_summary({})
        summary["total_users"] = len(all_org_users)

        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_get_device_by_ip_address(self, param):
        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))

        action_result = self.add_action_result(ActionResult(dict(param)))

        ip_address = param["ip_address"]

        org_id = param.get("org_id", "")

        # Validate IP address format using regex
        ip_pattern = re.compile(r"^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$")
        if not ip_pattern.match(ip_address):
            return action_result.set_status(phantom.APP_ERROR, f"Invalid IP address format: {ip_address}")

        # Use find_device_by_attribute to find the device by Public IP
        device = self.find_device_by_attribute(org_id, ["ip_addrs"], ip_address)

        # if we didn't find a match using the Public IP, try private IPs
        if not device:
            self.save_progress("Device not found using public IP. Trying private IPs...")
            device = self.find_device_by_attribute(org_id, ["ip_addrs_private"], ip_address)

        # if we don't find any matches at all
        if not device:
            return action_result.set_status(phantom.APP_ERROR, f"Device with IP address {ip_address} not found")

        action_result.add_data(device)

        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_list_groups(self, param):
        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))

        action_result = self.add_action_result(ActionResult(dict(param)))

        endpoint = AUTOMOX_GROUPS_LIST_ENDPOINT

        path_params = None
        query_params = {"o": param.get("org_id")}

        all_groups, ret_val = self._fetch_paginated_data(endpoint, path_params, query_params, action_result)

        if phantom.is_fail(ret_val):
            return action_result.get_status()

        action_result.add_data(all_groups)

        summary = action_result.update_summary({})
        summary["total_groups"] = len(all_groups)

        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_get_command_queues(self, param):
        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))

        action_result = self.add_action_result(ActionResult(dict(param)))

        base_endpoint = AUTOMOX_COMMAND_QUEUE_LIST_ENDPOINT

        path_params = {"device_id": param["device_id"]}

        query_params = {"o": param.get("org_id")}

        endpoint = self._build_url(base_endpoint, path_params, query_params)

        # make rest call
        ret_val, response = self._make_rest_call(endpoint, action_result, params=None, headers=self._headers)

        if phantom.is_fail(ret_val):
            return action_result.get_status()

        action_result.add_data(response)

        # Add a dictionary that is made up of the most important values from data into the summary
        summary = action_result.update_summary({})
        summary["total_commands_in_queue"] = len(response)

        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_remove_user_from_account(self, param):
        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))

        action_result = self.add_action_result(ActionResult(dict(param)))

        base_endpoint = AUTOMOX_REMOVE_USER_FROM_ACCOUNT_ENDPOINT

        path_params = {"account_id": param["account_id"], "user_id": param["user_id"]}

        query_params = None

        endpoint = self._build_url(base_endpoint, path_params, query_params)

        # make rest call
        ret_val, response = self._make_rest_call(endpoint, action_result, params=None, headers=self._headers, method="delete")

        if phantom.is_fail(ret_val):
            return action_result.get_status()

        action_result.add_data(response)

        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_update_device(self, param):
        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))

        action_result = self.add_action_result(ActionResult(dict(param)))

        base_endpoint = AUTOMOX_DEVICE_SPECIFIC_ENDPOINT

        # Extract params
        device_id = param["device_id"]
        exception = param["exception"]
        server_group_id = param["server_group_id"]
        org_id = param.get("org_id")
        tags = param.get("tags")
        custom_name = param.get("custom_name")

        # Validate and process tags
        if tags:
            # Check if the string is a valid comma-separated value
            if not re.match(r"^[a-zA-Z0-9_]+(,[a-zA-Z0-9_]+)*$", tags.strip()):
                return action_result.set_status(
                    phantom.APP_ERROR,
                    "Invalid tags: Tags must be a comma-separated list of alphanumeric values or underscores (e.g., 'tag1,tag2,tag3').",
                )

            # Split and process tags into a list
            tag_list = [tag.strip() for tag in tags.split(",")]

        path_params = {"device_id": device_id}

        query_params = {"o": org_id}

        body = {
            "server_group_id": server_group_id,
            "exception": exception,
            "tags": tag_list,
            **({"custom_name": custom_name} if custom_name is not None else {}),
        }

        # Serialize the body to JSON for proper formatting (else tags have single quotes around them)
        json_body = json.dumps(body)

        endpoint = self._build_url(base_endpoint, path_params, query_params)

        # make rest call
        ret_val, response = self._make_rest_call(endpoint, action_result, data=json_body, headers=self._headers, method="put")

        if phantom.is_fail(ret_val):
            return action_result.get_status()

        action_result.add_data(response)

        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_delete_device(self, param):
        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))

        action_result = self.add_action_result(ActionResult(dict(param)))

        base_endpoint = AUTOMOX_DEVICE_SPECIFIC_ENDPOINT

        path_params = {"device_id": param["device_id"]}

        query_params = {"o": param.get("org_id")}

        endpoint = self._build_url(base_endpoint, path_params, query_params)

        ret_val, response = self._make_rest_call(endpoint, action_result, params=None, headers=self._headers, method="delete")

        if phantom.is_fail(ret_val):
            return action_result.get_status()

        action_result.add_data(response)

        return action_result.set_status(phantom.APP_SUCCESS)

    def handle_action(self, param):
        ret_val = phantom.APP_SUCCESS

        # Get the action that we are supposed to execute for this App Run
        action_id = self.get_action_identifier()

        self.debug_print("action_id", self.get_action_identifier())

        if action_id == "run_worklet":
            ret_val = self._handle_run_worklet(param)

        if action_id == "list_policies":
            ret_val = self._handle_list_policies(param)

        if action_id == "list_devices":
            ret_val = self._handle_list_devices(param)

        if action_id == "list_organizations":
            ret_val = self._handle_list_organizations(param)

        if action_id == "get_device_software":
            ret_val = self._handle_get_device_software(param)

        if action_id == "get_device":
            ret_val = self._handle_get_device(param)

        if action_id == "get_device_by_hostname":
            ret_val = self._handle_get_device_by_hostname(param)

        if action_id == "list_organization_users":
            ret_val = self._handle_list_organization_users(param)

        if action_id == "get_device_by_ip_address":
            ret_val = self._handle_get_device_by_ip_address(param)

        if action_id == "list_groups":
            ret_val = self._handle_list_groups(param)

        if action_id == "get_command_queues":
            ret_val = self._handle_get_command_queues(param)

        if action_id == "remove_user_from_account":
            ret_val = self._handle_remove_user_from_account(param)

        if action_id == "update_device":
            ret_val = self._handle_update_device(param)

        if action_id == "delete_device":
            ret_val = self._handle_delete_device(param)

        if action_id == "test_connectivity":
            ret_val = self._handle_test_connectivity(param)

        return ret_val

    def finalize(self):
        # Save the state, this data is saved across actions and app upgrades
        self.save_state(self._state)
        return phantom.APP_SUCCESS


def main():
    import argparse

    argparser = argparse.ArgumentParser()

    argparser.add_argument("input_test_json", help="Input Test JSON file")
    argparser.add_argument("-u", "--username", help="username", required=False)
    argparser.add_argument("-p", "--password", help="password", required=False)

    args = argparser.parse_args()
    session_id = None

    username = args.username
    password = args.password

    if username is not None and password is None:
        # User specified a username but not a password, so ask
        import getpass

        password = getpass.getpass("Password: ")

    if username and password:
        try:
            login_url = AutomoxConnector._get_phantom_base_url() + "/login"

            print("Accessing the Login page")
            r = requests.get(login_url, verify=False)
            csrftoken = r.cookies["csrftoken"]

            data = dict()
            data["username"] = username
            data["password"] = password
            data["csrfmiddlewaretoken"] = csrftoken

            headers = dict()
            headers["Cookie"] = "csrftoken=" + csrftoken
            headers["Referer"] = login_url

            print("Logging into Platform to get the session id")
            r2 = requests.post(login_url, verify=False, data=data, headers=headers)
            session_id = r2.cookies["sessionid"]
        except Exception as e:
            print("Unable to get session id from the platform. Error: " + str(e))
            exit(1)

    with open(args.input_test_json) as f:
        in_json = f.read()
        in_json = json.loads(in_json)
        print(json.dumps(in_json, indent=4))

        connector = AutomoxConnector()
        connector.print_progress_message = True

        if session_id is not None:
            in_json["user_session_token"] = session_id
            connector._set_csrf_info(csrftoken, headers["Referer"])

        ret_val = connector._handle_action(json.dumps(in_json), None)
        print(json.dumps(json.loads(ret_val), indent=4))

    exit(0)


if __name__ == "__main__":
    main()
