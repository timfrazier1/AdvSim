"""
"""

import phantom.rules as phantom
import json
from datetime import datetime, timedelta

def on_start(container):
    phantom.debug('on_start() called')
    
    # call 'format_3' block
    format_3(container=container)

    return

def format_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('format_1() called')
    
    template = """eventcreate /id 999 /D \"started test for {0}\" /T INFORMATION /L application"""

    # parameter list for template variable replacement
    parameters = [
        "artifact:*.cef.destinationAddress",
    ]

    phantom.format(container=container, template=template, parameters=parameters, name="format_1")

    write_started_event(container=container)

    return

def run_supplied_command(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('run_supplied_command() called')
    
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'run_supplied_command' call
    container_data = phantom.collect2(container=container, datapath=['artifact:*.cef.command', 'artifact:*.id'])
    results_data_1 = phantom.collect2(container=container, datapath=['write_started_event:action_result.parameter.ip_hostname', 'write_started_event:action_result.parameter.context.artifact_id'], action_results=results)

    parameters = []
    
    # build parameters list for 'run_supplied_command' call
    for container_item in container_data:
        for results_item_1 in results_data_1:
            if results_item_1[0]:
                parameters.append({
                    'shell_id': "",
                    'parser': "",
                    'ip_hostname': results_item_1[0],
                    'command': container_item[0],
                    'arguments': "",
                    'async': "",
                    'command_id': "",
                    # context (artifact id) is added to associate results with the artifact
                    'context': {'artifact_id': results_item_1[1]},
                })

    phantom.act("run command", parameters=parameters, app={ "name": 'Windows Remote Management' }, callback=join_format_2, name="run_supplied_command")

    return

def write_started_event(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('write_started_event() called')
    
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'write_started_event' call
    container_data = phantom.collect2(container=container, datapath=['artifact:*.cef.destinationAddress', 'artifact:*.id'])
    formatted_data_1 = phantom.get_format_data(name='format_1')

    parameters = []
    
    # build parameters list for 'write_started_event' call
    for container_item in container_data:
        if container_item[0]:
            parameters.append({
                'shell_id': "",
                'parser': "",
                'ip_hostname': container_item[0],
                'async': "",
                'script_str': formatted_data_1,
                'script_file': "",
                'command_id': "",
                # context (artifact id) is added to associate results with the artifact
                'context': {'artifact_id': container_item[1]},
            })

    phantom.act("run script", parameters=parameters, app={ "name": 'Windows Remote Management' }, callback=format_command_1, name="write_started_event")

    return

def write_ended_event(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('write_ended_event() called')
    
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'write_ended_event' call
    results_data_1 = phantom.collect2(container=container, datapath=['write_started_event:action_result.parameter.ip_hostname', 'write_started_event:action_result.parameter.context.artifact_id'], action_results=results)
    formatted_data_1 = phantom.get_format_data(name='format_2')

    parameters = []
    
    # build parameters list for 'write_ended_event' call
    for results_item_1 in results_data_1:
        if results_item_1[0]:
            parameters.append({
                'shell_id': "",
                'parser': "",
                'ip_hostname': results_item_1[0],
                'async': "",
                'script_str': formatted_data_1,
                'script_file': "",
                'command_id': "",
                # context (artifact id) is added to associate results with the artifact
                'context': {'artifact_id': results_item_1[1]},
            })

    phantom.act("run script", parameters=parameters, app={ "name": 'Windows Remote Management' }, callback=format_4, name="write_ended_event")

    return

def decision_2(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('decision_2() called')

    # check for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        action_results=results,
        conditions=[
            ["artifact:*.cef.os", "==", "windows"],
        ])

    # call connected blocks if condition 1 matched
    if matched_artifacts_1 or matched_results_1:
        format_1(action=action, success=success, container=container, results=results, handle=handle)
        return

    # check for 'elif' condition 2
    matched_artifacts_2, matched_results_2 = phantom.condition(
        container=container,
        action_results=results,
        conditions=[
            ["artifact:*.cef.os", "==", "linux"],
        ])

    # call connected blocks if condition 2 matched
    if matched_artifacts_2 or matched_results_2:
        return

    # check for 'elif' condition 3
    matched_artifacts_3, matched_results_3 = phantom.condition(
        container=container,
        action_results=results,
        conditions=[
            ["artifact:*.cef.os", "==", "macos"],
        ])

    # call connected blocks if condition 3 matched
    if matched_artifacts_3 or matched_results_3:
        return

    return

def decision_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('decision_1() called')

    # check for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        action_results=results,
        conditions=[
            ["filtered-data:filter_1:condition_1:format_command_1:action_result.data.*.executor.name", "==", "powershell"],
        ])

    # call connected blocks if condition 1 matched
    if matched_artifacts_1 or matched_results_1:
        powershell_test(action=action, success=success, container=container, results=results, handle=handle)
        return

    # check for 'elif' condition 2
    matched_artifacts_2, matched_results_2 = phantom.condition(
        container=container,
        action_results=results,
        conditions=[
            ["filtered-data:filter_1:condition_1:format_command_1:action_result.data.*.executor.name", "==", "command_prompt"],
        ])

    # call connected blocks if condition 2 matched
    if matched_artifacts_2 or matched_results_2:
        cmd_test(action=action, success=success, container=container, results=results, handle=handle)
        return

    # call connected blocks for 'else' condition 3
    run_supplied_command(action=action, success=success, container=container, results=results, handle=handle)

    return

def powershell_test(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('powershell_test() called')
    
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'powershell_test' call
    results_data_1 = phantom.collect2(container=container, datapath=['write_started_event:action_result.parameter.ip_hostname', 'write_started_event:action_result.parameter.context.artifact_id'], action_results=results)
    filtered_results_data_1 = phantom.collect2(container=container, datapath=["filtered-data:filter_1:condition_1:format_command_1:action_result.data.*.executor.command", "filtered-data:filter_1:condition_1:format_command_1:action_result.parameter.context.artifact_id"])

    parameters = []
    
    # build parameters list for 'powershell_test' call
    for results_item_1 in results_data_1:
        for filtered_results_item_1 in filtered_results_data_1:
            if results_item_1[0]:
                parameters.append({
                    'shell_id': "",
                    'parser': "",
                    'ip_hostname': results_item_1[0],
                    'async': "",
                    'script_str': filtered_results_item_1[0],
                    'script_file': "",
                    'command_id': "",
                    # context (artifact id) is added to associate results with the artifact
                    'context': {'artifact_id': results_item_1[1]},
                })

    phantom.act("run script", parameters=parameters, app={ "name": 'Windows Remote Management' }, callback=join_format_2, name="powershell_test")

    return

def format_command_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('format_command_1() called')
    
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'format_command_1' call
    container_data = phantom.collect2(container=container, datapath=['artifact:*.cef.os', 'artifact:*.cef.test_id', 'artifact:*.cef.input_arguments', 'artifact:*.id'])

    parameters = []
    
    # build parameters list for 'format_command_1' call
    for container_item in container_data:
        if container_item[0] and container_item[1]:
            parameters.append({
                'supported_os': container_item[0],
                'attack_id': container_item[1],
                'input_arguments': container_item[2],
                # context (artifact id) is added to associate results with the artifact
                'context': {'artifact_id': container_item[3]},
            })

    phantom.act("format command", parameters=parameters, app={ "name": 'Atomic Red Team' }, callback=filter_1, name="format_command_1", parent_action=action)

    return

def cmd_test(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('cmd_test() called')
    
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'cmd_test' call
    results_data_1 = phantom.collect2(container=container, datapath=['write_started_event:action_result.parameter.ip_hostname', 'write_started_event:action_result.parameter.context.artifact_id'], action_results=results)
    filtered_results_data_1 = phantom.collect2(container=container, datapath=["filtered-data:filter_1:condition_1:format_command_1:action_result.data.*.executor.command", "filtered-data:filter_1:condition_1:format_command_1:action_result.parameter.context.artifact_id"])

    parameters = []
    
    # build parameters list for 'cmd_test' call
    for results_item_1 in results_data_1:
        for filtered_results_item_1 in filtered_results_data_1:
            if results_item_1[0]:
                parameters.append({
                    'ip_hostname': results_item_1[0],
                    'command': filtered_results_item_1[0].split(' ', 1)[0],
                    'arguments': filtered_results_item_1[0].split(' ', 1)[1],
                    'parser': "",
                    'async': True,
                    'command_id': "",
                    'shell_id': "",
                    # context (artifact id) is added to associate results with the artifact
                    'context': {'artifact_id': results_item_1[1]},
                })

    phantom.act("run command", parameters=parameters, app={ "name": 'Windows Remote Management' }, callback=join_format_2, name="cmd_test")

    return

def filter_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('filter_1() called')

    # collect filtered artifact ids for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        action_results=results,
        conditions=[
            ["Path", "not in", "format_command_1:action_result.data.*.executor.arg_types"],
        ],
        name="filter_1:condition_1")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        decision_1(action=action, success=success, container=container, results=results, handle=handle, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    return

def format_3(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('format_3() called')
    
    template = """Kicking off red team test: {0}  on machine with IP address: {1}"""

    # parameter list for template variable replacement
    parameters = [
        "artifact:*.cef.test_id",
        "artifact:*.cef.destinationAddress",
    ]

    phantom.format(container=container, template=template, parameters=parameters, name="format_3")

    post_data_1(container=container)

    return

def format_4(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('format_4() called')
    
    template = """Finished red team test: {0}  on machine with IP address: {1}"""

    # parameter list for template variable replacement
    parameters = [
        "artifact:*.cef.test_id",
        "artifact:*.cef.destinationAddress",
    ]

    phantom.format(container=container, template=template, parameters=parameters, name="format_4")

    post_data_2(container=container)

    return

def post_data_2(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('post_data_2() called')
    
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'post_data_2' call
    results_data_1 = phantom.collect2(container=container, datapath=['post_data_1:action_result.parameter.host', 'post_data_1:action_result.parameter.source_type', 'post_data_1:action_result.parameter.source', 'post_data_1:action_result.parameter.context.artifact_id'], action_results=results)
    formatted_data_1 = phantom.get_format_data(name='format_4')

    parameters = []
    
    # build parameters list for 'post_data_2' call
    for results_item_1 in results_data_1:
        parameters.append({
            'index': "",
            'host': results_item_1[0],
            'source_type': results_item_1[1],
            'data': formatted_data_1,
            'source': results_item_1[2],
            # context (artifact id) is added to associate results with the artifact
            'context': {'artifact_id': results_item_1[3]},
        })

    phantom.act("post data", parameters=parameters, app={ "name": 'Splunk' }, name="post_data_2")

    return

def post_data_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('post_data_1() called')

    # collect data for 'post_data_1' call
    formatted_data_1 = phantom.get_format_data(name='format_3')

    parameters = []
    
    splunk_status_source_type = phantom.collect(container, "artifact:*.cef.splunk_status_source_type")
    
    # build parameters list for 'post_data_1' call
    parameters.append({
        'index': "",
        'host': splunk_status_source_type,
        'source_type': "advsim:atr",
        'data': formatted_data_1,
        'source': "Phantom",
    })

    phantom.act("post data", parameters=parameters, app={ "name": 'Splunk' }, callback=decision_2, name="post_data_1")

    return

def format_2(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('format_2() called')
    
    template = """eventcreate /id 999 /D \"ended test for {0}\" /T INFORMATION /L application"""

    # parameter list for template variable replacement
    parameters = [
        "write_started_event:action_result.parameter.ip_hostname",
    ]

    phantom.format(container=container, template=template, parameters=parameters, name="format_2")

    write_ended_event(container=container)

    return

def join_format_2(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('join_format_2() called')
    
    # if the joined function has already been called, do nothing
    if phantom.get_run_data(key='join_format_2_called'):
        return

    # no callbacks to check, call connected block "format_2"
    phantom.save_run_data(key='join_format_2_called', value='format_2', auto=True)

    format_2(container=container, handle=handle)
    
    return

def on_finish(container, summary):
    phantom.debug('on_finish() called')
    # This function is called after all actions are completed.
    # summary of all the action and/or all detals of actions 
    # can be collected here.

    # summary_json = phantom.get_summary()
    # if 'result' in summary_json:
        # for action_result in summary_json['result']:
            # if 'action_run_id' in action_result:
                # action_results = phantom.get_action_results(action_run_id=action_result['action_run_id'], result_data=False, flatten=False)
                # phantom.debug(action_results)

    return