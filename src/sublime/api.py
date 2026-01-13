"""Sublime API client."""

import os
import json
import time
import datetime
from datetime import datetime
from datetime import timedelta

import requests
import structlog

from sublime.__version__ import __version__
from sublime.error import RateLimitError, InvalidRequestError, APIError, AuthenticationError
from sublime.util import load_config

LOGGER = structlog.get_logger()


class Sublime(object):
    """
    Sublime API client.

    :param api_key: Key used to access the API.
    :type api_key: str

    """

    _NAME = "Sublime"
    _BASE_URL = os.environ.get('BASE_URL')
    #_BASE_URL = _BASE_URL if _BASE_URL else "https://analyzer.sublime.security"
    _BASE_URL = _BASE_URL if _BASE_URL else "https://api.platform.sublimesecurity.com"
    _API_VERSION = "v1"
    _EP_ME = "me"
    _EP_FEEDBACK = "feedback"
    _EP_MESSAGES_CREATE = "messages/create"
    _EP_MESSAGES_ANALYZE = "messages/analyze"
    _EP_PRIVACY_ACCEPT = "privacy/accept"
    _EP_PRIVACY_DECLINE = "privacy/decline"
    _EP_NOT_IMPLEMENTED = "request/{subcommand}"

    # NOTE: since there are two api versions, you must add logic to
    # _is_public_endpoint if you add a public v0 path
    _API_VERSION_PUBLIC = "v0"
    _EP_PUBLIC_BINEXPLODE_SCAN = "binexplode/scan"
    _EP_PUBLIC_BINEXPLODE_SCAN_RESULT = "binexplode/scan/{id}"
    _EP_PUBLIC_TASK_STATUS = "tasks/{id}"

    _EP_ORG_CHILD = "organizations/mine/child-organizations"
    _EP_ADMIN_AUTH = "admin-auth"
    
    _EP_LISTS = "lists"
    _EP_LIST_ENTRIES = "lists/{id}/entries"
    _EP_LIST_ENTRIES_ENTRY = "lists/{id}/entries/entry"
    
    _EP_MESSAGE_IMAGE = "messages/{id}/image"
    _EP_MESSAGE_IMAGE_LINK = "messages/{id}/image_link"

    _EP_USER_REPORTS = "user-reports"
    
    _EP_USERS = "users"
    _EP_USERS_INDIV = "users/{id}"

    _EP_MESSAGE_SOURCES = "message-sources"
    _EP_MAILBOXES = "mailboxes"
    
    _EP_ACTIVATE_MAILBOXES = "message-sources/{id}/mailboxes/activate"


    def __init__(self, api_key=None):
        if api_key is None:
            config = load_config()
            api_key = config.get("api_key")
        self._api_key = api_key
        self.session = requests.Session()

    def _is_public_endpoint(self, endpoint):
        if endpoint in [  # This list doesn't work if the endpoint is formatted
                self._EP_PUBLIC_BINEXPLODE_SCAN, 
                self._EP_MESSAGES_ANALYZE, 
                self._EP_MESSAGES_CREATE, 
                self._EP_LIST_ENTRIES, 
                self._EP_ORG_CHILD, 
                self._EP_USER_REPORTS, 
                self._EP_MAILBOXES]:
            return True
        if endpoint.startswith("binexplode") or endpoint.startswith("tasks/") or endpoint.startswith("lists"): #FIXME this is not sustainable.  find a better way.
            return True

        return False

    def _request(self, endpoint, request_type='GET', params=None, json=None, headers=None):
        """Handle the requesting of information from the API.

        :param endpoint: Endpoint to send the request to.
        :type endpoint: str
        :param params: Request parameters.
        :type param: dict
        :param json: Request's JSON payload.
        :type json: dict
        :returns: Response's JSON payload
        :rtype: dict
        :raises InvalidRequestError: when HTTP status code is 400 or 404
        :raises RateLimitError: when HTTP status code is 429
        :raises APIError: for all other 4xx or 5xx status codes

        """

        if params is None:
            params = {}
        
        if headers is None:
            headers = { "User-Agent": "sublime-cli/{}".format(__version__) }
        else:
            headers["User-Agent"] = "sublime-cli/{}".format(__version__)
        
        if self._api_key:
            headers["Key"] = self._api_key
        
        is_public = self._is_public_endpoint(endpoint)
        api_version = self._API_VERSION_PUBLIC if is_public else self._API_VERSION

        url = "/".join([self._BASE_URL, api_version, endpoint])

        # LOGGER.debug("Sending API request...", url=url, headers=headers, params=params, json=json)

        if request_type == 'GET':
            response = self.session.get(
                url, headers=headers, params=params, json=json
            )
        elif request_type == 'POST':
            response = self.session.post(
                    url, headers=headers, json=json
            )
        elif request_type == 'PUT':
            response = self.session.put(
                    url, headers=headers, json=json
            )
        elif request_type == 'PATCH':
            response = self.session.patch(
                    url, headers=headers, json=json
            )
        elif request_type == 'DELETE':
            response = self.session.delete(
                    url, headers=headers, params=params
            )
        else:
            raise NotImplementedError("Method {} is not implemented", request_type)

        if "application/json" in response.headers.get("Content-Type", ""):
            # 204 has no content and will trigger an exception
            if response.status_code != 204:
                body = response.json()
            else:
                body = None
        else:
            body = response.text

        if response.status_code >= 400:
            self._handle_error_response(response, body)

        return body, response.headers

    def _handle_error_response(self, resp, resp_body):
        try:
            error_data = resp_body["error"]
            message = error_data["message"]
        except:
            raise APIError(
                    "Invalid response from API: %r (HTTP response code "
                    "was %d)" % (resp_body, resp.status_code),
                    status_code=resp.status_code,
                    headers=resp.headers)

        if resp.status_code in [400, 404]:
            err = InvalidRequestError(
                    message=message,
                    status_code=resp.status_code,
                    headers=resp.headers)
        elif resp.status_code == 401:
            err = AuthenticationError(
                    message=message,
                    status_code=resp.status_code,
                    headers=resp.headers)
        elif resp.status_code == 429:
            err = RateLimitError(
                    message=message,
                    status_code=resp.status_code,
                    headers=resp.headers)
        else:
            err = APIError(
                    message=message,
                    status_code=resp.status_code,
                    headers=resp.headers)

        raise err

    def me(self):
        """Get information about the currently authenticated Sublime user."""

        endpoint = self._EP_ME
        response, _ = self._request(endpoint, request_type='GET')
        return response

    def create_message(self, raw_message, mailbox_email_address=None, message_type=None):
        """Create a Message Data Model from a raw message.

        :param raw_message: Base64 encoded raw message
        :type raw_message: str
        :param mailbox_email_address: Email address of the mailbox
        :type mailbox_email_address: str
        :param message_type: The type of message from the perspective of your organization (inbound, internal, outbound)
        :type message_type: str
        :rtype: dict
        
        """

        # LOGGER.debug("Creating a message data model...")

        body = {}
        body["raw_message"] = raw_message

        if mailbox_email_address:
            body["mailbox_email_address"] = mailbox_email_address
        if message_type:
            if message_type == "inbound":
                body["message_type"] = {"inbound": True}
            elif message_type == "internal":
                body["message_type"] = {"internal": True}
            elif message_type == "outbound":
                body["message_type"] = {"outbound": True}
            else:
                raise Exception("Unsupported message_type")

        endpoint = self._EP_MESSAGES_CREATE
        response, _ = self._request(endpoint, request_type='POST', json=body)
        return response

    def analyze_message(self, raw_message, rules, queries, run_all_detection_rules=False, run_active_detection_rules=False, run_all_insights=False):
        """Analyze a Message Data Model against a list of rules or queries.

        :param raw_message: Base64 encoded raw message
        :type raw_message: str
        :param rules: Rules to run
        :type rules: list
        :param queries: Queries to run
        :type queries: list
        :rtype: dict
        :param run_all_detection_rules: whether to run all detection rules against the given message
        :type run_all_detection_rules: bool
        :param run_active_detection_rules: whether to run active detection rules against the given message
        :type run_active_detection_rules: bool
        :param run_all_insights: whether to run all insight queries against the given message
        :type run_all_insights: bool

        """
        
        # LOGGER.debug("Analyzing message data model...")

        body = {
            "raw_message": raw_message,
            "rules": rules,
            "queries": queries,
            "run_all_detection_rules": run_all_detection_rules,
            "run_active_detection_rules": run_active_detection_rules,
            "run_all_insights": run_all_insights,
        }

        endpoint = self._EP_MESSAGES_ANALYZE
        response, _ = self._request(endpoint, request_type='POST', json=body)
        return response

    def poll_task_status(self, task_id):
        while True:
            endpoint = self._EP_PUBLIC_TASK_STATUS.format(id=task_id)
            response, _ = self._request(endpoint, request_type='GET')
            if response.get("state"):
                if response["state"] in ("pending", "started", "retrying"):
                    time.sleep(1)
                    continue
                else:
                    # state in ("succeeded", "failed")
                    break

        return response

    def binexplode_scan(self, file_contents, file_name):
        """Scan a binary using binexplode.

        :param file_contents: Base64 encoded file contents
        :type file_contents: str
        :param file_name: File name
        :type file_name: str
        :rtype: dict

        """

        # LOGGER.debug("Scanning binary using binexplode...")

        body = {"file_contents": file_contents, "file_name": file_name}

        endpoint = self._EP_PUBLIC_BINEXPLODE_SCAN
        response, _ = self._request(endpoint, request_type='POST', json=body)
        task_id = response.get('task_id')
        if task_id:
            response = self.poll_task_status(task_id)
            if response.get("state") == "succeeded":
                endpoint = self._EP_PUBLIC_BINEXPLODE_SCAN_RESULT.format(id=task_id)
                response, _ = self._request(endpoint, request_type='GET')

        return response

    def feedback(self, feedback):
        """Send feedback directly to the Sublime team.

        :param feedback: Feedback
        :type feedback: str
        :rtype: dict

        """

        # LOGGER.debug("Sending feedback...")

        body = {"feedback": feedback}

        endpoint = self._EP_FEEDBACK
        response, _ = self._request(endpoint, request_type='POST', json=body)
        return response

    def privacy_ack(self, accept):
        """Sends privacy acknowledgement to the Sublime server."""
        if accept:
            endpoint = self._EP_PRIVACY_ACCEPT
        else:
            endpoint = self._EP_PRIVACY_DECLINE

        response, _ = self._request(endpoint, request_type='POST')
        return response

    def create_child_org(self, org_name):
        """Creates a child organization (for multi-tenancy)"""

        endpoint = self._EP_ORG_CHILD

        params = { "name": org_name }

        response, _  = self._request(endpoint, request_type="POST", json=params)

        return response['id']

    def create_approval_link(self, org_id, provider):
        """Cretes an admin approval link for a message source"""
        
        if provider not in ["microsoft", "google"]:
            raise AttributeError("Provider must be microsoft or google")

        endpoint = self._EP_ADMIN_AUTH

        headers = { "x-sublime-child-organization": org_id }
        params = { "provider": provider }


        response, _ = self._request(endpoint, request_type="POST", headers=headers, json=params)

        return response['url']

    def create_list(self, name, descr = "Custom List"):

        list_id = self.get_list_id(name)
        
        if list_id:
            LOGGER.info(f"Attempt to create existing list {name}, returned existing id {list_id}")
            return list_id
        
        endpoint = self._EP_LISTS 

        params = {"description": descr, "name": name }
        
        r, _ = self._request(endpoint, request_type="POST", json=params)

        return  r['id']

    def retrieve_lists(self, list_id=None, list_name=None):
        """Retrieves filtered lists from the Sublime server"""

        endpoint = self._EP_LISTS 

        params = {"entry_type": "string"}
        if list_id != None:
            params['id']=list_id
        if list_name != None:
            params['name']=list_name

        response, _ = self._request(endpoint, request_type='GET', params=params)

        return response

    def get_list_id(self, name):
        """Retrieves a list ID from a supplied list name"""
        
        r = self.retrieve_lists(list_name=name)

        if isinstance(r, dict):
            if r['lists'] is not None:
                list_id = r['lists'][0]['id']
                LOGGER.debug(f"Found list id {list_id}")
                return list_id
        LOGGER.debug(f"No ID found for list {name}")
        return None

    def get_list(self, list_name=None, list_id=None):
        """Retrieves a full list from either an ID or list name"""

        if not list_id and not list_name:
            raise AttributeError("Either list_id or list_name must be defined") 
        if list_name:
            list_id = self.get_list_id(list_name)
            if not list_id:
                raise AttributeError(f"Passed list name {list_name} does not exist")

        endpoint = self._EP_LIST_ENTRIES.format(id=list_id)
        
        response, _ = self._request(endpoint, request_type='GET')

        return response

    def set_list(self, content, list_id=None, list_name=None, create_if_missing=False):
        """Sets list content on the server, must have a list_id or list_name passed"""
       
        if not list_id and not list_name:
            raise AttributeError("Either list_id or list_name must be defined") 
        if list_name:
            list_id = self.get_list_id(list_name)
            if not list_id:
                if create_if_missing:
                    list_id = self.create_list(name)
                else:
                    raise AttributeError(f"Passed list name {list_name} does not exist")

        if not isinstance(content, list):
            raise AttributeError("content must be a list of values")

        endpoint = self._EP_LIST_ENTRIES.format(id=list_id)
        
        response, _ = self._request(endpoint, request_type='PUT', json={"entries": content})

        return response
    
    def set_list_from_file(self, file, list_id=None, list_name=None):
        """Sets list content on the server from a supplied local file, returns number of lines set"""
       
        # this is redundant to the checks in set_list, but I didn't want to open/read the file prior to validating params
        if not list_id and not list_name:
            raise AttributeError("Either list_id or list_name must be defined") 
        if list_name:
            list_id = self.get_list_id(list_name)
            if not list_id:
                if create_if_missing:
                    list_id = self.create_list(name)
                else:
                    raise AttributeError(f"Passed list name {list_name} does not exist")

        with open(file, 'r', encoding='utf-8')as f:
            filedata = f.readlines()
        
        content = [s.rstrip() for s in filedata]

        self.set_list(content, list_id=list_id)

        return len(content)

    def add_list_entry(self, entry, list_id=None, list_name=None):
        """Adds a single list entry to a supplied list name or ID"""
        
        if not list_id and not list_name:
            raise AttributeError("Either list_id or list_name must be defined") 
        if list_name:
            list_id = self.get_list_id(list_name)
            if not list_id:
                raise AttributeError(f"Passed list name {list_name} does not exist")

        endpoint = self._EP_LIST_ENTRIES_ENTRY.format(id=list_id)

        params = { "string": entry }

        response, _  = self._request(endpoint, request_type="POST", json=params)

        return response


    def get_message_image(self, message_id):
        """Retrieves an image of an email message from the server"""

        endpoint = self._EP_MESSAGE_IMAGE.format(id=message_id)

        response, _ = self._request(endpoint, request_type='GET')

        return response

    def get_message_image_link(self, message_id, duration=600):
        """Retrieves a temporary link to an image of an email message.  Pass duration (in seconds) to specify how long the link lasts (default is 600)"""
        
        endpoint = self._EP_MESSAGE_IMAGE_LINK.format(id=message_id)

        params = { "report_label": label, "review_comment": comment }
        
        response, _ = self._request(endpoint, request_type='GET', params=params)

        return response

    def get_user_reports(self, starttime=False, endtime=datetime.isoformat(datetime.utcnow()) + "Z", lookback_days=False, limit=500):
        """Retrieves user reports.  You must pass either start or looback_days, end time defaults to now. Datetime format is ISO"""
        
        endpoint = self._EP_USER_REPORTS

        if not starttime and not lookback_days:
            raise AttributeError("Either endtime or lookback_days must be defined")

        if lookback_days:
            starttime = datetime.isoformat(datetime.utcnow() - timedelta(days=lookback_days)) + "Z"

        params = { "limit": limit, "reported_at[gte]": starttime, "reported_at[lt]": endtime }

        response, _ = self._request(endpoint, request_type='GET', params=params)

        return response

    def retrieve_users(self, user_id=None):
        """Retrieves users from the Sublime server"""

        if user_id == None:
            endpoint = self._EP_USERS
        else:
            endpoint = self._EP_USERS_INDIV.format(id=user_id)

        params = {"entry_type": "string"}

        response, _ = self._request(endpoint, request_type='GET', params=params)

        return response

    def find_user_by_email(self, user_email=None):
        """Finds a user record by the email address for that user"""

        if not user_email:
            raise AttributeError("user_email must be specified")

        # pull all users and find user email
        users = self.retrieve_users()
        LOGGER.debug(f"Found {len(users)} total users.  looking for email {user_email}")
        for user in users:
            if user['email_address'] == user_email:
                LOGGER.debug(f"Found user {user['id']}")
                return user

        raise AttributeError(f"user_email {user_email} not found")

    def update_user(self, user_id=None, user_email=None, new_data=None):
        """Updates a user record by applying a dictionary of new_data"""

        if not isinstance(new_data, dict):
            raise AttributeError("new_data must be a dictionary")

        allowed = ["role","first_name","last_name","email_address"]
        for k,v in new_data.items():
            if k not in allowed:
                raise AttributeError("new_data may only contain role, first_name, last_name, or email_address")

        if user_id:
            user=self.retrieve_users(user_id=user_id)
        elif user_email:
            user=self.find_user_by_email(user_email=user_email)
        else:
            raise AttributeError("user_id or user_email must be specified")

        # create a dict of either the new value or existing value
        update={}
        for key in ["role","first_name","last_name","email_address"]:
            update[key] = new_data.get(key, user[key])
            LOGGER.debug(f"updating {key} for user, old value is {user[key]}, new value is {update[key]}")

        endpoint = self._EP_USERS_INDIV.format(id=user['id'])

        response, _ = self._request(endpoint, request_type='POST', json=update)

        return response

    def delete_user(self, user_id=None, user_email=None):
        """Deletes a user record by ID or email"""

        if user_id:
            user=self.retrieve_users(user_id=user_id)
        elif user_email:
            user=self.find_user_by_email(user_email=user_email)
        else:
            raise AttributeError("user_id or user_email must be specified")


        endpoint = self._EP_USERS_INDIV.format(id=user['id'])

        response, _ = self._request(endpoint, request_type='DELETE')

        return response

    def retrieve_message_sources(self):
        """Retrieves message sources"""

        params = {}

        endpoint = self._EP_MESSAGE_SOURCES
        response, _ = self._request(endpoint, request_type='GET', params=params)

        return response

    def retrieve_mailboxes(self, search=None, mailbox_types=None, email_addresses=None, active=None, message_source_id=None):
        """Retrieves mailboxes and automatically handles pagnation"""

        params = {
                "entry_type": "string",
                "search": search,
                "mailbox_types": mailbox_types,
                "email_addresses": email_addresses,
                "active": active,
                "message_source_id": message_source_id,
                "limit": 500
                }

        endpoint = self._EP_MAILBOXES
        response, _ = self._request(endpoint, request_type='GET', params=params)

        mailboxes = response['mailboxes']

        if response['total'] > 500: # there is an api limit of 500, so now we need to get counts and stuff
            LOGGER.debug(f"retrieve mailboxes found {response['total']} mailboxes but limit is 500. downloading additional entries")
            marker = 500

            while marker < response['total']:
                params['offset'] = marker
                response, _ = self._request(endpoint, request_type='GET', params=params)
                mailboxes.extend(response['mailboxes'])
                marker += 500

            LOGGER.debug(f"Total mailboxes retrieved was {len(mailboxes)}")

        return mailboxes

    def summarize_mailboxes(self):
        """Returns a dictionary with mailbox counts"""
        counts = {
                'activeusers': 0,
                'inactiveusers': 0,
                'activeothers': 0,
                'inactiveothers': 0
                }

        usermailboxes = self.retrieve_mailboxes(mailbox_types='user')
        othermailboxes = self.retrieve_mailboxes(mailbox_types='other')

        for um in usermailboxes:
            if um['active']:
                counts['activeusers']+=1
            else:
                counts['inactiveusers']+=1

        for om in othermailboxes:
            if om['active']:
                counts['activeothers']+=1
            else:
                counts['inactiveothers']+=1

        return counts

    def activate_mailboxes(self, search=None, mailbox_types=None, email_addresses=None, message_source_id=None):
        """Attempts to activate mailboxes.  Providing a search, mailbox_type, email_address, or message_source_id constrains the activity to just those mailboxes, otherwise all are selected."""

        message_source_ids = []
        #if a message source id is provided, fairly simple, otherwise we iterate
        if message_source_id == None:
            LOGGER.debug(f"Getting message sources")
            message_sources = self.retrieve_message_sources()
            for s in message_sources['message_sources']:
                message_source_ids.append(s['id'])

            LOGGER.debug(f"Found {len(message_source_ids)} message sources")
        else:
            message_sources_ids[0] = (message_source_id)

        # Activate calls are per message source

        totalcount = 0
        for s in message_source_ids:

            LOGGER.debug(f"Getting mailboxes for message source id {s}")
            
            mailboxes = self.retrieve_mailboxes(search=search, mailbox_types=mailbox_types, email_addresses=email_addresses, active=False, message_source_id=s)

            print(mailboxes)
            
            mailbox_ids = []
            for m in mailboxes:
                mailbox_ids.append(m['id'])
                totalcount += 1

            if len(mailbox_ids) == 0:
                LOGGER.debug(f"No unactivated mailboxes found for message source {s}")
                continue
           
            endpoint = self._EP_ACTIVATE_MAILBOXES.format(id=s)
            response, _ = self._request(endpoint, request_type='POST', json={ "mailbox_ids": mailbox_ids })
            
        
        LOGGER.debug("Finished activate call")
        return totalcount


    def _not_implemented(self, subcommand_name):
        """Send request for a not implemented CLI subcommand.

        :param subcommand_name: Name of the CLI subcommand
        :type subcommand_name: str

        """
        endpoint = self._EP_NOT_IMPLEMENTED.format(subcommand=subcommand_name)
        response, _ = self._request(endpoint)
        return response


class JSONEncoder(json.JSONEncoder):
    def default(self, obj):
        if isinstance(obj, datetime.datetime):
            return obj.isoformat()
        return json.JSONEncoder.default(self, obj)
