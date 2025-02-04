import argparse
import json
import re
from argparse import ArgumentParser, Namespace
from math import ceil
from typing import Any, Dict, List, Optional, Tuple, TypedDict, Union
from urllib.parse import quote, urlencode

import phantom.app as phantom
import requests
from bs4 import BeautifulSoup
from phantom.action_result import ActionResult
from phantom.base_connector import BaseConnector

from automox_consts import (
    AUTOMOX_COMMAND_QUEUE_LIST_ENDPOINT,
    AUTOMOX_CONSOLE_API_URL,
    AUTOMOX_DEVICE_LIST_ENDPOINT,
    AUTOMOX_DEVICE_LIST_PACKAGES_ENDPOINT,
    AUTOMOX_DEVICE_SPECIFIC_ENDPOINT,
    AUTOMOX_GROUPS_LIST_ENDPOINT,
    AUTOMOX_ORGS_LIST_ENDPOINT,
    AUTOMOX_POLICY_LIST_ENDPOINT,
    AUTOMOX_POLICY_RUN_ENDPOINT,
    AUTOMOX_REMOVE_USER_FROM_ACCOUNT_ENDPOINT,
    AUTOMOX_USERS_LIST_ENDPOINT,
    AUTOMOX_USERS_LIST_SPECIFIC_ENDPOINT,
    AUTOMOX_USERS_SELF_ENDPOINT,
)


class RetVal(tuple):
    def __new__(cls, val1, val2=None):
        return tuple.__new__(RetVal, (val1, val2))


class Params:
    """
    A class to handle various parameter types used in API requests.
    """

    def __init__(self, query_params=None, path_params=None, **kwargs) -> None:
        if path_params is None:
            path_params = {}
        if query_params is None:
            query_params = {}

        self._query_params = query_params # {"description": "Query parameters for the API request"}
        self._path_params = path_params # {"description": "Path parameters for the API request"}
        self._aux_params = dict(kwargs) # {"description": "Additional parameters for the API request"}

    def get_query_params(self) -> Dict[str, str]:
        """Get a copy of query parameters"""
        return self._query_params.copy() if self._query_params else {}

    def get_query_param_by_key(self, key: str) -> Union[str, None]:
        """Get a specific query parameter value by key"""
        return self._query_params.get(key, None)

    def get_path_params(self) -> Dict[str, str]:
        """Get a copy of path parameters"""
        return self._path_params.copy() if self._path_params else {}

    def get_path_param_by_key(self, key: str) -> Union[str, None]:
        """Get a specific path parameter value by key"""
        return self._path_params.get(key, None)

    def get_aux_params(self) -> Dict[str, Any]:
        """Get a copy of auxiliary parameters"""
        return self._aux_params.copy()

    def get_aux_param_by_key(self, key: str) -> Union[str, None]:
        """Get a specific auxiliary parameter value by key"""
        return self._aux_params.get(key, None)

    def to_dict(self) -> Dict[str, Dict[str, Any]]:
        """Get all parameters as a dictionary"""
        return {
            "query_params": self.get_query_params(),
            "path_params": self.get_path_params(),
            "aux_params": self.get_aux_params()
        }

    def get_params(self) -> Tuple[Dict[str, str], Dict[str, str]]:
        """Get parameters for URL building"""
        return self.get_path_params(), self.get_query_params()


class Device(TypedDict, total=False):
    id: int  # {"description": "Device ID"}
    name: str  # {"description": "Device hostname/name"}
    display_name: str  # {"description": "Custom display name"}
    ip_addrs: List[str]  # {"description": "List of public IP addresses"}
    ip_addrs_private: List[str]  # {"description": "List of private IP addresses"}
    os_family: str  # {"description": "Operating system family"}
    os_name: str  # {"description": "Operating system name"}
    os_version: str  # {"description": "Operating system version"}
    server_group_id: int  # {"description": "Group ID the device belongs to"}
    tags: List[str]  # {"description": "List of tags assigned to device"}
    total_count: int  # {"description": "Total count for paginated responses"}
    status: str  # {"description": "Device status"}
    last_refresh: str  # {"description": "Last device refresh timestamp"}
    custom_name: str  # {"description": "User-defined device name"}
    exception: bool  # {"description": "Whether device has 'exclude from reports' flag"}


class AutomoxConnector(BaseConnector):
    class AutomoxAction:
        base_endpoint: str  # {"description": "Base API endpoint for the action"}
        params: Params  # {"description": "Parameters for the API request"}
        summary_key: str  # {"description": "Key used in action summary response"}
        handle_function: callable  # {"description": "Function that handles the action logic"}
        fetch_function: callable  # {"description": "Function that fetches data from the API"}
        fetch_function_method: str  # {"description": "HTTP method to use for the API request", "allowed_values": ["get", "post", "put", "delete"]}

        def __init__(
            self,
            base_endpoint: str,
            handle_function: callable,
            fetch_function: callable = None,
            fetch_function_method: str = "get",
            params: Optional[Union[Params, Dict[str, Any]]] = None,
            summary_key: str = None,
        ):
            # Convert dict to Params at creation time
            self.params = Params() if params is None else (
                params if isinstance(params, Params) else Params(**params)
            )
            self.base_endpoint = base_endpoint
            self.params = params
            self.summary_key = summary_key
            self.handle_function = handle_function
            self.fetch_function = fetch_function
            self.fetch_function_method = fetch_function_method.lower()

    def __init__(self):
        super(AutomoxConnector, self).__init__()

        self._page_limit = None
        self._headers = None
        self._state = None
        self._base_url = None

    def initialize(self) -> int:
        config = self.get_config()

        # Load the state in initialize, use it to store data
        # that needs to be accessed across actions
        self._state = self.load_state()
        self._base_url = AUTOMOX_CONSOLE_API_URL
        self._headers = {"Content-Type": "application/json", "Authorization": f"Bearer {config['ax_console_api_key']}"}
        self._page_limit = int(config.get("page_limit", 100))

        return phantom.APP_SUCCESS

    def _get_endpoint(self, action: AutomoxAction) -> str:
        return self._build_url_for_action(
            base_endpoint=action.base_endpoint,
            action=action
        )

    def _build_url_for_action(self, base_endpoint: str, action: AutomoxAction) -> str:
        """
        Constructs a full URL by replacing placeholders in the base endpoint and appending query parameters

        Args:
            base_endpoint (str): Base API endpoint for the action
            action (AutomoxAction): Action object containing parameters
        """
        path_params, query_params = action.params.get_params()

        # Replace path params
        if path_params:
            for key, value in path_params.items():
                safe_value = quote(str(value), safe="")
                placeholder = f"{{{key}}}"

                if placeholder in base_endpoint:
                    base_endpoint = base_endpoint.replace(placeholder, safe_value)
                else:
                    self.debug_print(f"Warning: Path param key '{key}' not found in endpoint.")

        # Filter out None or empty values from query parameters
        if query_params:
            query_params = {k: v for k, v in query_params.items() if v}

        # Append query params
        full_url = base_endpoint
        if query_params:
            query_string = urlencode(query_params)
            full_url = f"{base_endpoint}?{query_string}"

        self.debug_print(f"The full URL we're returning: {full_url}")
        return full_url

    @staticmethod
    def _process_empty_response(response: requests.Response, action_result: ActionResult) -> RetVal:
        if response.status_code in [200, 204]:
            return RetVal(phantom.APP_SUCCESS, {})

        return RetVal(action_result.set_status(phantom.APP_ERROR, "Empty response and no information in the header"), None)

    @staticmethod
    def _process_html_response(response: requests.Response, action_result: ActionResult) -> RetVal:
        status_code = response.status_code

        try:
            soup = BeautifulSoup(response.text, "html.parser")
            error_text = soup.text
            split_lines = error_text.split("\n")
            split_lines = [x.strip() for x in split_lines if x.strip()]
            error_text = "\n".join(split_lines)
        except Exception as e:
            error_text = f"Cannot parse error details: {e}"

        message = f"Status Code: {status_code}. Data from server:\n{error_text}\n"

        message = message.replace("{", "{{").replace("}", "}}")
        return RetVal(action_result.set_status(phantom.APP_ERROR, message), None)

    @staticmethod
    def _process_json_response(r: requests.Response, action_result: ActionResult) -> RetVal:
        try:
            resp_json = r.json()
        except Exception as e:
            return RetVal(action_result.set_status(phantom.APP_ERROR, f"Unable to parse JSON response. Error: {str(e)}"), None)

        if 200 <= r.status_code < 400:
            return RetVal(phantom.APP_SUCCESS, resp_json)

        message = f"Error from server. Status Code: {r.status_code} Data from server: {r.text.replace('{', '{{').replace('}', '}}')}"

        return RetVal(action_result.set_status(phantom.APP_ERROR, message), None)

    def _process_response(self, r: requests.Response, action_result: ActionResult) -> RetVal:
        if hasattr(action_result, "add_debug_data"):
            action_result.add_debug_data({"r_status_code": r.status_code})
            action_result.add_debug_data({"r_text": r.text})
            action_result.add_debug_data({"r_headers": r.headers})

        if "json" in r.headers.get("Content-Type", ""):
            return self._process_json_response(r, action_result)
        elif "html" in r.headers.get("Content-Type", ""):
            return self._process_html_response(r, action_result)

        if not r.text:
            return self._process_empty_response(r, action_result)

        message = f"Can't process response from server. Status Code: {r.status_code} Data from server: {r.text.replace('{', '{{').replace('}', '}}')}"

        return RetVal(action_result.set_status(phantom.APP_ERROR, message), None)

    def _make_rest_call(
        self, endpoint: str, action_result: ActionResult, method: str = "get", headers: Optional[Dict[str, str]] = None, **kwargs
    ) -> RetVal:
        config = self.get_config()

        resp_json = None

        try:
            request_func = getattr(requests, method)
        except AttributeError:
            return RetVal(action_result.set_status(phantom.APP_ERROR, f"Invalid method: {method}"), resp_json)

        url = self._base_url + endpoint

        try:
            r = request_func(url, verify=config.get("verify_server_cert", False), headers=headers, **kwargs)
        except Exception as e:
            return RetVal(action_result.set_status(phantom.APP_ERROR, f"Error Connecting to server. Details: {str(e)}"), resp_json)

        return self._process_response(r, action_result)

    def _fetch_paginated_data(
        self, 
        endpoint: str, 
        params: Union[Params, Dict[str, Any]], 
        action_result: ActionResult, 
        headers: Dict[str, str]
    ) -> Tuple[int, List[Dict[str, Any]]]:
        """Fetches all pages of data from a paginated API endpoint."""
        params_obj = params if isinstance(params, Params) else Params(**params)
        paginated_params = self.first_page(params_obj)
        all_items = []

        while True:
            ret_val, response = self._make_rest_call(
                endpoint=endpoint,
                action_result=action_result,
                params=paginated_params.get_query_params(),
                headers=headers
            )

            if phantom.is_fail(ret_val):
                return phantom.APP_ERROR, []

            all_items.extend(response)

            if len(response) < self._page_limit:
                break

            self.debug_print("Getting next page...")
            paginated_params = self.next_page(paginated_params)

        return phantom.APP_SUCCESS, all_items

    def first_page(self, params: Union[Params, Dict[str, Any]]) -> Params:
        """Initialize pagination parameters"""
        if not isinstance(params, Params):
            params = Params(**params)
        
        query_params = params.get_query_params()
        query_params.update({
            "limit": self._page_limit,
            "page": 0
        })
        
        return Params(query_params=query_params, path_params=params.get_path_params())

    @staticmethod
    def next_page(params: Params) -> Params:
        """Get parameters for the next page"""
        query_params = params.get_query_params()
        current_page = query_params.get("page", 0)
        query_params["page"] = current_page + 1
        query_params["limit"] = query_params.get("limit", 100)
        
        return Params(query_params=query_params, path_params=params.get_path_params())

    def _format_for_display(self, value: Any) -> str:
        """
        Format any value into a human-readable string representation.
        This is because the table display in SOAR sanitizes the data and does not display nested json nicely.
        
        Args:
            value: Any value to format
            
        Returns:
            str: Human-readable string representation
        """
        if isinstance(value, list):
            # If list contains dicts, extract key info
            if value and isinstance(value[0], dict):
                # For rbac_roles, use organization_id instead of id
                if all(isinstance(x, dict) and "name" in x and "organization_id" in x for x in value):
                    return ", ".join(f"{x['name']} ({x['organization_id']})" for x in value)
                # Try common key combinations for name/id pairs
                if all(isinstance(x, dict) and "name" in x and "id" in x for x in value):
                    return ", ".join(f"{x['name']} ({x['id']})" for x in value)
                # Fallback to first value or str representation
                return ", ".join(str(next(iter(x.values()))) if x else str(x) for x in value)
            # Simple list - join with commas
            return ", ".join(str(x) for x in value)
        
        if isinstance(value, dict):
            # Extract the most meaningful parts of a dict
            meaningful_keys = ["name", "id", "value", "type"]
            values = []
            for key in meaningful_keys:
                if key in value:
                    values.append(f"{value[key]}")
            if values:
                return " - ".join(values)
            # Fallback to first value if no meaningful keys found
            return str(next(iter(value.values()))) if value else ""
            
        # Handle basic types
        return str(value)

    def _format_list_fields(self, data: Dict[str, Any], field_name: str) -> Dict[str, str]:
        """Format list fields into a readable string representation for table display"""
        result = {}
        if field_name in data:
            result[field_name] = self._format_for_display(data[field_name])
        return result

    def _get_total_device_count(self, endpoint: str, action_result: ActionResult) -> int:
        ret_val, response = self._make_rest_call(
            endpoint=endpoint,
            action_result=action_result,
            params={"limit": 1},  # Fetch only one device to get the total count
            headers=self._headers,
        )

        if phantom.is_fail(ret_val):
            raise Exception(f"Failed to get total device count: {action_result.get_message()}")

        return response[0].get("total_count", 0)

    @staticmethod
    def _find_matching_device(devices: List[Device], attributes: List[str], value: str) -> Optional[Device]:
        """
        Searches for a device matching specified attributes and value.

        Args:
            devices (List[Device]): List of device dictionaries to search
            attributes (List[str]): Device attributes to check
            value (str): Value to match against

        Returns:
            Optional[Device]: Matching device dictionary or None if not found
        """
        for device in devices:
            for attr in attributes:
                attr_value = device.get(attr)

                if attr_value is None:
                    continue
                if isinstance(attr_value, str) and attr_value.casefold() == value.casefold():
                    return device
                if isinstance(attr_value, list) and value.lower() in (v.lower() for v in attr_value):
                    return device
        return None

    @staticmethod
    def _is_valid_number(value: Any) -> bool:
        """
        Check if value is valid (not None and either a number or any other non-None type)
        
        Args:
            value: Value to check
            
        Returns:
            bool: True if value is valid, False otherwise
        """
        return value is not None

    def remove_null_values(self, item: Union[Dict[str, Any], List[Any], Any]) -> Union[Dict[str, Any], List[Any], Any]:
        """
        Recursively remove null values from a dictionary or list
        """
        if isinstance(item, dict):
            return {
                key: self.remove_null_values(value)
                for key, value in item.items()
                if self._is_valid_number(value) and self._is_valid_number(self.remove_null_values(value))
            }
        elif isinstance(item, list):
            return [
                self.remove_null_values(value)
                for value in item
                if self._is_valid_number(value) and self._is_valid_number(self.remove_null_values(value))
            ]
        return item

    def find_device_by_attribute_with_value(
        self, 
        endpoint: str, 
        attributes: List[str], 
        value: str, 
        action_result: ActionResult,
        params: Optional[Union[Params, Dict[str, Any]]] = None
    ) -> Optional[Device]:
        """
        Searches through all devices to find one matching specified attributes with given value.

        Args:
            endpoint (str): API endpoint for device listing
            attributes (List[str]): Device attributes to check
            value (str): Value to match against the attributes
            action_result (ActionResult): Action result object for status tracking
            params (Optional[Union[Params, Dict[str, Any]]]): Parameters for the request

        Returns:
            Optional[Device]: Matching device dictionary or None if not found

        Raises:
            Exception: If API call fails
        """
        total_devices = self._get_total_device_count(endpoint, action_result)
        if total_devices is None:
            return None

        max_pages = ceil(total_devices / self._page_limit)
        paginated_params = self.first_page(params)
        
        for current_page in range(max_pages):
            self.debug_print(f"Fetching devices with params: {paginated_params.to_dict()}")

            ret_val, devices = self._make_rest_call(
                endpoint=endpoint,
                action_result=action_result,
                params=paginated_params.get_query_params(),
                headers=self._headers
            )

            if phantom.is_fail(ret_val):
                self.debug_print(f"Failed to get devices: {action_result.get_message()}")
                raise Exception(f"Failed to get devices: {action_result.get_message()}")

            device = self._find_matching_device(devices, attributes, value)
            if device:
                return self.remove_null_values(device)  # type: ignore

            if len(devices) < self._page_limit:
                break

            paginated_params = self.next_page(paginated_params)
            current_page += 1

        self.debug_print(f"Device relating to {value} not found")
        return None

    # Action logic
    def _handle_generic(self, action: AutomoxAction) -> int:
        self.save_progress(f"In action handler for: {self.get_action_identifier()}")

        action_result = self.add_action_result(ActionResult(action.params.to_dict()))
        endpoint = self._get_endpoint(action)

        fetch_function_kwargs = {
            "endpoint": endpoint,
            "params": action.params.get_query_params(),
            "action_result": action_result,
            "headers": self._headers,
        }

        # Include POST body if fetch_function_method is POST
        if action.fetch_function_method.lower() == "post":
            fetch_function_kwargs["method"] = "post"
            fetch_function_kwargs["data"] = json.dumps(action.params.get_aux_param_by_key("body"))

        # Do a DELETE if fetch_function_method is DELETE
        if action.fetch_function_method.lower() == "delete":
            fetch_function_kwargs["method"] = "delete"

        ret_val, response = action.fetch_function(**fetch_function_kwargs)

        if phantom.is_fail(ret_val):
            return action_result.get_status()

        action_result.add_data(response)

        if action.summary_key:
            summary = action_result.update_summary({})
            summary[action.summary_key] = len(response)

        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_get_device_by_ip_address(self, action: AutomoxAction) -> int:
        """
        Handles the get_device_by_ip_address action.

        Args:
            action (AutomoxAction): Action configuration object

        Returns:
            int: Action status code (success/failure)
        """
        self.save_progress(f"In action handler for: {self.get_action_identifier()}")

        action_result = self.add_action_result(ActionResult(action.params.to_dict()))
        endpoint = self._get_endpoint(action)

        ip_address = action.params.get_aux_param_by_key("ip_address")
        ip_pattern = re.compile(r"^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$") # Validate IP address format using regex

        if not ip_pattern.match(ip_address):
            return action_result.set_status(phantom.APP_ERROR, f"Invalid IP address format: {ip_address}")

        try:
            # Pass the params to find_device_by_attribute_with_value
            device = self.find_device_by_attribute_with_value(
                endpoint=endpoint, 
                attributes=["ip_addrs"], 
                value=ip_address, 
                action_result=action_result,
                params=action.params
            )

            # if we didn't find a match using the Public IP, try private IPs
            if not device:
                self.save_progress("Device not found using public IP. Trying private IPs...")
                device = self.find_device_by_attribute_with_value(
                    endpoint=endpoint, 
                    attributes=["ip_addrs_private"], 
                    value=ip_address, 
                    action_result=action_result,
                    params=action.params
                )

            # if we don't find any matches at all
            if not device:
                return action_result.set_status(phantom.APP_ERROR, f"Device with IP address {ip_address} not found")

            action_result.add_data(device if device else {})

            return action_result.set_status(phantom.APP_SUCCESS)

        except Exception as e:
            self.debug_print(f"Exception occurred: {str(e)}")
            return action_result.set_status(phantom.APP_ERROR, f"Error finding device by IP address: {str(e)}")

    def _handle_get_device_by_hostname(self, action: AutomoxAction) -> int:
        """
        Handles the get_device_by_hostname action.

        Args:
            action (AutomoxAction): Action configuration object

        Returns:
            int: Action status code (success/failure)
        """
        self.save_progress(f"In action handler for: {self.get_action_identifier()}")

        action_result = self.add_action_result(ActionResult(action.params.to_dict()))
        endpoint = self._get_endpoint(action)

        hostname = action.params.get_aux_param_by_key("hostname")
        self.debug_print(f"Searching for device with hostname: {hostname}")

        try:
            device = self.find_device_by_attribute_with_value(
                endpoint=endpoint, 
                attributes=["name"], 
                value=hostname, 
                action_result=action_result,
                params=action.params
            )

            if not device:
                return action_result.set_status(phantom.APP_ERROR, f"Device with hostname {hostname} not found")

            action_result.add_data(device)

            return action_result.set_status(phantom.APP_SUCCESS)

        except Exception as e:
            self.debug_print(f"Exception occurred: {str(e)}")
            return action_result.set_status(phantom.APP_ERROR, f"Error finding device by hostname: {str(e)}")

    def _handle_update_device(self, action: AutomoxAction):
        """
        Handles the update_device action.

        Args:
            action (AutomoxAction): Action configuration object

        Returns:
            int: Action status code (success/failure)
        """
        self.save_progress(f"In action handler for: {self.get_action_identifier()}")

        action_result = self.add_action_result(ActionResult(action.params.to_dict()))
        endpoint = self._get_endpoint(action)

        # Extract aux params for POST body
        exception = action.params.get_aux_param_by_key("exception")
        server_group_id = action.params.get_aux_param_by_key("server_group_id")
        tags = action.params.get_aux_param_by_key("tags")
        custom_name = action.params.get_aux_param_by_key("custom_name")

        # Validate and process tags
        tag_list = []
        if tags:
            # Check if the string is a valid comma-separated value
            if not re.match(r"^[a-zA-Z0-9_]+(,[a-zA-Z0-9_]+)*$", tags.strip()):
                return action_result.set_status(
                    phantom.APP_ERROR,
                    "Invalid tags: Tags must be a comma-separated list of alphanumeric values or underscores (e.g., 'tag1,tag2,tag3').",
                )

            # Split and process tags into a list
            tag_list = [tag.strip() for tag in tags.split(",")]

        body = {
            "server_group_id": server_group_id,
            "exception": exception,
            "tags": tag_list,
            **({"custom_name": custom_name} if custom_name is not None else {}),
        }

        # Serialize the body to JSON for proper formatting (else tags have single quotes around them)
        json_body = json.dumps(body)

        # make rest call
        ret_val, response = self._make_rest_call(endpoint, action_result, data=json_body, headers=self._headers, method="put")

        if phantom.is_fail(ret_val):
            return action_result.get_status()

        action_result.add_data(response)

        return action_result.set_status(phantom.APP_SUCCESS)
    
    def _handle_list_organization_users(self, action: AutomoxAction) -> int:
        """
        Handles both list_organization_users and get_organization_user actions.
        If user_id is provided in the params, fetches a single user, otherwise lists all users.

        Args:
            action (AutomoxAction): Action configuration object

        Returns:
            int: Action status code (success/failure)
        """
        self.save_progress(f"In action handler for: {self.get_action_identifier()}")

        action_result = self.add_action_result(ActionResult(action.params.to_dict()))
        endpoint = self._get_endpoint(action)

        # Check if we're getting a single user
        user_id = action.params.get_path_param_by_key("user_id")
        
        if user_id:
            ret_val, users = self._make_rest_call(endpoint, action_result, method="get", headers=self._headers)
            users = [users] if ret_val == phantom.APP_SUCCESS else []
        else:
            ret_val, users = self._fetch_paginated_data(
                endpoint=endpoint,
                params=action.params,
                action_result=action_result,
                headers=self._headers
            )

        if phantom.is_fail(ret_val):
            return action_result.get_status()

        for user in users:
            formatted_user = user.copy()

            # Combine first and last name
            if "firstname" in user and "lastname" in user:
                formatted_user["name"] = f"{user['firstname']} {user['lastname']}"

            # Format the orgs and rbac_roles as JSON strings
            formatted_user.update(self._format_list_fields(user, "orgs"))
            formatted_user.update(self._format_list_fields(user, "rbac_roles"))
            
            # Format tags if present
            if "tags" in user:
                formatted_user.update(self._format_list_fields(user, "tags"))

            action_result.add_data(formatted_user)

        if action.summary_key and not user_id:  # Only add summary for list operation
            summary = action_result.update_summary({})
            summary[action.summary_key] = len(users)

        return action_result.set_status(phantom.APP_SUCCESS)

    def handle_action(self, param: Dict[str, Any]) -> int:
        """
        Main action handler for the connector. This is also where the action mapping/config is defined.

        Args:
            param (dict): Parameters for the action

        Returns:
            int: Action status code (success/failure)
        """
        # Get the action that we are supposed to execute for this App Run
        action_id = self.get_action_identifier()
        self.debug_print("action_id ", action_id)

        if action_id == phantom.ACTION_ID_INGEST_ON_POLL:
            start_time = time.time()
            result = self._on_poll(action)
            end_time = time.time()
            diff_time = end_time - start_time
            human_time = str(timedelta(seconds=int(diff_time)))

            self.save_progress(f"Time taken: {human_time}")

            return result

        action_mapping = {
            "test_connectivity": AutomoxConnector.AutomoxAction(
                base_endpoint=AUTOMOX_USERS_SELF_ENDPOINT,
                handle_function=self._handle_generic,
                fetch_function=self._make_rest_call,
                params=Params(),
                fetch_function_method="get",
            ),
            "list_groups": AutomoxConnector.AutomoxAction(
                base_endpoint=AUTOMOX_GROUPS_LIST_ENDPOINT,
                handle_function=self._handle_generic,
                fetch_function=self._fetch_paginated_data,
                fetch_function_method="get",
                params=Params(query_params={"o": param.get("org_id")}),
                summary_key="total_groups",
            ),
            "run_policy": AutomoxConnector.AutomoxAction(
                base_endpoint=AUTOMOX_POLICY_RUN_ENDPOINT,
                handle_function=self._handle_generic,
                fetch_function=self._make_rest_call,
                fetch_function_method="post",
                params=Params(
                    query_params={"o": param.get("org_id")},
                    path_params={"policy_id": param.get("policy_id")},
                    body={"action": "remediateAll", "serverId": param.get("device_id")},
                ),
            ),
            "list_policies": AutomoxConnector.AutomoxAction(
                base_endpoint=AUTOMOX_POLICY_LIST_ENDPOINT,
                handle_function=self._handle_generic,
                fetch_function=self._fetch_paginated_data,
                params=Params(query_params={"o": param.get("org_id")}),
                summary_key="total_policies",
            ),
            "list_organizations": AutomoxConnector.AutomoxAction(
                base_endpoint=AUTOMOX_ORGS_LIST_ENDPOINT,
                handle_function=self._handle_generic,
                fetch_function=self._make_rest_call,
                params=Params(),
                summary_key="total_orgs",
            ),
            "list_organization_users": AutomoxConnector.AutomoxAction(
                base_endpoint=AUTOMOX_USERS_LIST_ENDPOINT,
                handle_function=self._handle_list_organization_users,
                params=Params(query_params={"o": param.get("org_id")}),
                summary_key="total_users",
            ),
            "get_organization_user": AutomoxConnector.AutomoxAction(
                base_endpoint=AUTOMOX_USERS_LIST_SPECIFIC_ENDPOINT,
                handle_function=self._handle_list_organization_users,
                params=Params(
                    query_params={"o": param.get("org_id")}, 
                    path_params={"user_id": param.get("user_id")}
                ),
            ),
            "list_devices": AutomoxConnector.AutomoxAction(
                base_endpoint=AUTOMOX_DEVICE_LIST_ENDPOINT,
                handle_function=self._handle_generic,
                fetch_function=self._fetch_paginated_data,
                params=Params(query_params={"o": param.get("org_id")}),
                summary_key="total_devices",
            ),
            "get_device": AutomoxConnector.AutomoxAction(
                base_endpoint=AUTOMOX_DEVICE_SPECIFIC_ENDPOINT,
                handle_function=self._handle_generic,
                fetch_function=self._make_rest_call,
                params=Params(query_params={"o": param.get("org_id")}, path_params={"device_id": param.get("device_id")}),
                summary_key="",
            ),
            "get_device_by_hostname": AutomoxConnector.AutomoxAction(
                base_endpoint=AUTOMOX_DEVICE_LIST_ENDPOINT,
                handle_function=self._handle_get_device_by_hostname,
                params=Params(query_params={"o": param.get("org_id")}, hostname=param.get("hostname")),
                summary_key="",
            ),
            "get_device_by_ip_address": (
                AutomoxConnector.AutomoxAction(
                    base_endpoint=AUTOMOX_DEVICE_LIST_ENDPOINT,
                    handle_function=self._handle_get_device_by_ip_address,
                    params=Params(query_params={"o": param.get("org_id")}, ip_address=param.get("ip_address")),
                )
            ),
            "get_device_software": AutomoxConnector.AutomoxAction(
                base_endpoint=AUTOMOX_DEVICE_LIST_PACKAGES_ENDPOINT,
                handle_function=self._handle_generic,
                fetch_function=self._fetch_paginated_data,
                params=Params(query_params={"o": param.get("org_id")}, path_params={"device_id": param.get("device_id")}),
                summary_key="num_of_packages",
            ),
            "get_command_queues": AutomoxConnector.AutomoxAction(
                base_endpoint=AUTOMOX_COMMAND_QUEUE_LIST_ENDPOINT,
                handle_function=self._handle_generic,
                fetch_function=self._make_rest_call,
                params=Params(query_params={"o": param.get("org_id")}, path_params={"device_id": param.get("device_id")}),
                summary_key="total_commands_in_queue",
            ),
            "remove_user_from_account": AutomoxConnector.AutomoxAction(
                base_endpoint=AUTOMOX_REMOVE_USER_FROM_ACCOUNT_ENDPOINT,
                handle_function=self._handle_generic,
                fetch_function=self._make_rest_call,
                fetch_function_method="delete",
                params=Params(path_params={"account_id": param.get("account_id"), "user_id": param.get("user_id")}),
            ),
            "update_device": AutomoxConnector.AutomoxAction(
                base_endpoint=AUTOMOX_DEVICE_SPECIFIC_ENDPOINT,
                handle_function=self._handle_update_device,
                params=Params(
                    query_params={"o": param.get("org_id")},
                    path_params={"device_id": param.get("device_id")},
                    exception=param.get("exception"),
                    server_group_id=param.get("server_group_id"),
                    tags=param.get("tags"),
                    custom_name=param.get("custom_name"),
                ),
            ),
            "delete_device": AutomoxConnector.AutomoxAction(
                base_endpoint=AUTOMOX_DEVICE_SPECIFIC_ENDPOINT,
                handle_function=self._handle_generic,
                fetch_function=self._make_rest_call,
                fetch_function_method="delete",
                params=Params(query_params={"o": param.get("org_id")}, path_params={"device_id": param.get("device_id")}),
            ),
        }

        action_execution_status = phantom.APP_SUCCESS

        if action_id not in action_mapping:
            self.debug_print("Action ID not found in action_mapping: ", action_id)
        else:
            action_object = action_mapping[action_id]
            self.debug_print("Executing action function: ", action_object.handle_function)
            action_execution_status = action_object.handle_function(action_object)
        return action_execution_status

    def finalize(self) -> int:
        # Save the state, this data is saved across actions and app upgrades
        self.save_state(self._state)
        return phantom.APP_SUCCESS


def parse_args():
    argparser = argparse.ArgumentParser()

    argparser.add_argument("input_test_json", help="Input Test JSON file")
    argparser.add_argument("-u", "--username", help="username", required=False)
    argparser.add_argument("-p", "--password", help="password", required=False)

    return argparser.parse_args()

def login(args: argparse.Namespace):
    login_url = f"{AutomoxConnector._get_phantom_base_url()}/login"

    print("Accessing the Login page")
    r = requests.get(login_url, verify=False)
    csrftoken = r.cookies["csrftoken"]

    data = dict()
    data["username"] = args.username
    data["password"] = args.password
    data["csrfmiddlewaretoken"] = csrftoken

    headers = dict()
    headers["Cookie"] = "csrftoken=" + csrftoken
    headers["Referer"] = login_url

    print("Logging into Platform to get the session id")
    r2 = requests.post(login_url, verify=False, data=data, headers=headers)

    return r2.cookies["sessionid"]

def main():
    args = parse_args()

    session_id = None
    username = args.username
    password = args.password

    if username and not password:
        # User specified a username but not a password, so ask
        import getpass

        password = getpass.getpass("Password: ")

    if username and password:
        try:
            session_id = login(args=args)
        except Exception as e:
            print(f"Unable to get session id from the platform. Error: {str(e)}")
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
