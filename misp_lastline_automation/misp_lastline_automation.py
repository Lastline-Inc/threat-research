#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Module to automate calling 'lastline_import' on analysis links tagged as incomplete.

Configuration:
    You need to configure both MISP_URL and MISP_KEY variables.

Accepts the following options:
    -d: make the run a dry run; query the instance but do not persist changes.
    -e [event_id]: only process (if selected) attributes belonging to the specified event.

Usage:
    > /usr/bin/python3 /path_to_script/misp_lastline_automation/misp_lastline_automation.py

Better usage: you might want to run the script as cron job every 15 or 60 minutes.
    */15 * * * *   mispuser   /usr/bin/python3 /path_to_script/misp_lastline_automation.py

Note: both module and workflow are based on 'vmray_automation.py' by Koen Van Impe.
"""
import argparse
import json
import pymisp
import requests
import urllib.parse

# Suppress those "Unverified HTTPS request is being made"
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


MISP_URL = ""

MISP_KEY = ""

VERIFY_CERT = False

TAG_INCOMPLETE = "workflow:state='incomplete'"

TAG_COMPLETE = "workflow:state='complete'"


def _call_import_module(config, analysis_link):
    """
    Call the MISP import module on the provided analysis link.

    :param dict[str, str] config: the configuration to use with the module
    :param str analysis_link: the analysis link
    :rtype: dict[str, any]
    :return: the parsed returned data
    :raise RuntimeError: if the server does not reply in a good way
    """
    # Call the import module
    misp_modules_url = "{}:{}/query".format(
        config["modules_url"],
        config["modules_port"],
    )
    misp_modules_body = json.dumps({
        "module": "lastline_import",
        "config": {
            "analysis_link": analysis_link,
            "api_key": config["api_key"],
            "api_token": config["api_token"],
            "username": config["username"],
            "password": config["password"],
        }
    })
    misp_modules_headers = {
        'Content-Type': 'application/json',
    }
    try:
        response = requests.post(
            misp_modules_url,
            data=misp_modules_body,
            headers=misp_modules_headers,
        )
    except Exception as e:
        raise RuntimeError("Error querying MISP modules: {}".format(str(e)))
    else:
        if response.status_code != 200:
            raise RuntimeError("Error querying MISP modules")
    return response.json()


def _get_attributes_with_analysis_link(misp, tag):
    """
    Get MISP attributes matching the provided tag and containing a valid analysis link

    :param ExpandedPyMISP misp: the misp instance
    :param str tag: the tag to match
    :rtype: list[Attributes]
    :return: the list of attributes matching that specific tag
    """
    print("Searching for attributes matching the tag '{}'".format(tag))
    response = misp.search(controller="attributes", tags=tag)
    if not response:
        print("No attributes found that match the tag '{}'".format(tag))
        return []

    attributes = response["Attribute"]
    if len(attributes) == 0:
        print("No attributes found that match the tag '{}'".format(tag))
        return []

    to_process = [x for x in attributes if "portal#/analyst/task" in x["value"]]
    if len(to_process) == 0:
        print("No attribute tagged '{}' contains a valid analysis link".format(tag))

    return to_process


def process_incomplete_attributes(
    misp,
    config,
    tag_incomplete,
    tag_complete,
    test_event_id=None,
    dry_run=False,
):
    """
    Search incomplete attributes and process not completed items.

    :param ExpandedPyMISP misp: the misp instance
    :param dict[str, str] config: the configuration
    :param str tag_incomplete: the not completed tag
    :param str tag_complete: the completed tag
    :param str test_event_id: optional test event id
    :param boolean dry_run: whether this is a dry run
    """
    # Get all the attributes satisfying the filter
    attributes = _get_attributes_with_analysis_link(misp, tag_incomplete)

    # Process each attribute
    for attribute in attributes:
        att_uuid = attribute['uuid']
        event_id = attribute['event_id']
        analysis_link = attribute["value"]
        print("Processing attribute {} for event {}".format(att_uuid, event_id))

        if test_event_id is not None and event_id != test_event_id:
            print("Skipping attributes related to event {} because in test mode".format(event_id))
            continue

        try:
            imported_data = _call_import_module(config, analysis_link)
            # Update the even with what we have learned so far
            event = misp.get_event(event_id, pythonify=True)
            for entity_type, entities in imported_data.get("results", []).items():
                if entity_type == "Tag":
                    for entity in entities:
                        tag = pymisp.MISPTag()
                        tag.name = entity["name"]
                        event.add_tag(tag)

                elif entity_type == "Object":
                    for entity in entities:
                        obj = pymisp.MISPObject("test")
                        obj.from_dict(**entity)
                        event.add_object(obj)

                else:
                    print("Skipping entity type '{}'".format(entity_type))

            if dry_run:
                print("This a dry-run. Would update event {}".format(event_id))
                print("This a dry-run. Would update tags for event {}".format(event_id))
            else:
                print("Updating event {}".format(event_id))
                misp.update_event(event)
                print("Updating tags for event {}".format(event_id))
                misp.untag(att_uuid, tag_incomplete)
                misp.tag(att_uuid, tag_complete)
        except Exception as e:
            print("Error processing attribute {} for event {}: {}".format(
                att_uuid, event_id, str(e)
            ))


def get_module_config(url, module_key, verify_cert):
    """
    Get the current module configuration from a MISP instance.

    :param str url: the URL to MISP instance
    :param str module_key: the key used for automation
    :param boolean verify_cert: whether to check the TLS certificate
    :rtype: dict[str, str]
    :return: the configuration of the Lastline module
    :raise RuntimeError: if the server does not reply in a good way
    :raise ValueError: if the configuration is not valid
    """
    try:
        response = requests.get(
            url=urllib.parse.urljoin(url, "servers/serverSettings.json"),
            verify=verify_cert,
            headers={
                'Content-Type': 'application/json',
                'Accept': 'application/json',
                'Authorization': module_key,
            },
        )

    except Exception as e:
        raise RuntimeError("Error querying MISP: {}".format(str(e)))
    else:
        if response.status_code != 200:
            raise RuntimeError("Error retrieving the MISP modules configuration")

    module_key_to_config_key = {
        "Plugin.Import_lastline_import_enabled": "enabled",
        "Plugin.Import_lastline_import_api_key": "api_key",
        "Plugin.Import_lastline_import_api_token": "api_token",
        "Plugin.Import_lastline_import_username": "username",
        "Plugin.Import_lastline_import_password": "password",
        "Plugin.Import_services_port": "modules_port",
        "Plugin.Import_services_url": "modules_url",
    }
    config = {}
    for setting in response.json().get("finalSettings", []):
        config_key = module_key_to_config_key.get(setting["setting"])
        if config_key:
            # Empty strings coalesce to None
            config[config_key] = setting["value"] or None

    # Do a sanity check
    if not config.get("enabled"):
        raise ValueError("The required import module is not enabled")

    # We support two types of authentication
    if not config.get("username") or not config.get("password"):
        if not config.get("api_key") or not config.get("api_token"):
            raise ValueError("The required import module is not configured")

    return config


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("-e", "--test-event-id", dest="test_event_id")
    parser.add_argument("-d", "--dry_run", action="store_true", dest="dry_run")
    args = parser.parse_args()

    misp_instance = pymisp.ExpandedPyMISP(MISP_URL, MISP_KEY, ssl=VERIFY_CERT)
    misp_config = get_module_config(MISP_URL, MISP_KEY, VERIFY_CERT)
    process_incomplete_attributes(
        misp_instance,
        misp_config,
        TAG_INCOMPLETE,
        TAG_COMPLETE,
        args.test_event_id,
        args.dry_run,
    )
