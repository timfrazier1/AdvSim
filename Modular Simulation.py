"""
"""

import phantom.rules as phantom
import json
from datetime import datetime, timedelta

def on_start(container):
    phantom.debug('on_start() called')
    
    # call 'format_1' block
    format_1(container=container)

    return

def decision_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('decision_1() called')

    container_data = phantom.collect2(container=container, datapath=['artifact:*.cef.test_id', 'artifact:*.id'])
    phantom.debug(container_data)
    tests_to_run = []
    for each_item in container_data:
        success, message, test_rows = phantom.get_list(list_name='Test Matrix', values=each_item[0])
        phantom.debug(
            'phantom.get_list results: success: {}, message: {}, execs: {}'.format(success, message, test_rows))
        for match in test_rows['matches']:
            tests_to_run.append(match['value'])
    phantom.debug(tests_to_run)
    """
    # call connected blocks if condition 1 matched
    if matched_artifacts_1 or matched_results_1:
        powershell_test(action=action, success=success, container=container, results=results, handle=handle)
        return

    # check for 'elif' condition 2
    matched_artifacts_2, matched_results_2 = phantom.condition(
        container=container,
        action_results=results,
        conditions=[
            ["artifact:*.cef.test_id", "in", "custom_list:Test Matrix"],
        ])

    # call connected blocks if condition 2 matched
    if matched_artifacts_2 or matched_results_2:
        cmd_test(action=action, success=success, container=container, results=results, handle=handle)
        return

    # call connected blocks for 'else' condition 3
    run_supplied_command(action=action, success=success, container=container, results=results, handle=handle)
    """
    return

def powershell_test(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('powershell_test() called')
    
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'powershell_test' call
    results_data_1 = phantom.collect2(container=container, datapath=['write_started_event:action_result.parameter.ip_hostname', 'write_started_event:action_result.parameter.context.artifact_id'], action_results=results)

    parameters = []
    
    # build parameters list for 'powershell_test' call
    for results_item_1 in results_data_1:
        if results_item_1[0]:
            parameters.append({
                'ip_hostname': results_item_1[0],
                'script_file': "",
                'script_str': "",
                'parser': "",
                'async': "",
                'command_id': "",
                'shell_id': "",
                # context (artifact id) is added to associate results with the artifact
                'context': {'artifact_id': results_item_1[1]},
            })

    phantom.act("run script", parameters=parameters, app={ "name": 'Windows Remote Management' }, callback=join_format_2, name="powershell_test")

    return

def cmd_test(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('cmd_test() called')
    
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'cmd_test' call
    container_data = phantom.collect2(container=container, datapath=['artifact:*.cef.destinationAddress', 'artifact:*.id'])

    parameters = []
    
    # build parameters list for 'cmd_test' call
    for container_item in container_data:
        if container_item[0]:
            parameters.append({
                'ip_hostname': container_item[0],
                'command': "",
                'arguments': "",
                'parser': "",
                'async': "",
                'command_id': "",
                'shell_id': "",
                # context (artifact id) is added to associate results with the artifact
                'context': {'artifact_id': container_item[1]},
            })

    phantom.act("run command", parameters=parameters, app={ "name": 'Windows Remote Management' }, callback=join_format_2, name="cmd_test")

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

def write_started_event(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('write_started_event() called')

    # collect data for 'write_started_event' call
    container_data = phantom.collect2(container=container, datapath=['artifact:*.cef.destinationAddress', 'artifact:*.id'])
    formatted_data_1 = phantom.get_format_data(name='format_1')

    parameters = []
    
    # build parameters list for 'write_started_event' call
    for container_item in container_data:
        if container_item[0]:
            parameters.append({
                'ip_hostname': container_item[0],
                'script_file': "",
                'script_str': formatted_data_1,
                'parser': "",
                'async': "",
                'command_id': "",
                'shell_id': "",
                # context (artifact id) is added to associate results with the artifact
                'context': {'artifact_id': container_item[1]},
            })

    phantom.act("run script", parameters=parameters, app={ "name": 'Windows Remote Management' }, callback=decision_1, name="write_started_event")

    return

def format_2(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('format_2() called')
    
    template = """eventcreate /id 999 /D \"ended test for {0}\" /T INFORMATION /L application"""

    # parameter list for template variable replacement
    parameters = [
        "artifact:*.cef.destinationAddress",
    ]

    phantom.format(container=container, template=template, parameters=parameters, name="format_2")

    write_ended_event(container=container)

    return

def join_format_2(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('join_format_2() called')
    
    # if the joined function has already been called, do nothing
    if phantom.get_run_data(key='join_format_2_called'):
        return

    # check if all connected incoming actions are done i.e. have succeeded or failed
    if phantom.actions_done([ 'run_supplied_command' ]):
        
        # save the state that the joined function has now been called
        phantom.save_run_data(key='join_format_2_called', value='format_2')
        
        # call connected block "format_2"
        format_2(container=container, handle=handle)
    
    return

def write_ended_event(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('write_ended_event() called')
    
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'write_ended_event' call
    results_data_1 = phantom.collect2(container=container, datapath=['write_started_event:action_result.parameter.ip_hostname', 'write_started_event:action_result.parameter.context.artifact_id'], action_results=results)

    parameters = []
    
    # build parameters list for 'write_ended_event' call
    for results_item_1 in results_data_1:
        if results_item_1[0]:
            parameters.append({
                'ip_hostname': results_item_1[0],
                'script_file': "",
                'script_str': "",
                'parser': "",
                'async': "",
                'command_id': "",
                'shell_id': "",
                # context (artifact id) is added to associate results with the artifact
                'context': {'artifact_id': results_item_1[1]},
            })

    phantom.act("run script", parameters=parameters, app={ "name": 'Windows Remote Management' }, name="write_ended_event")

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
                    'ip_hostname': results_item_1[0],
                    'command': container_item[0],
                    'arguments': "",
                    'parser': "",
                    'async': "",
                    'command_id': "",
                    'shell_id': "",
                    # context (artifact id) is added to associate results with the artifact
                    'context': {'artifact_id': results_item_1[1]},
                })

    phantom.act("run command", parameters=parameters, app={ "name": 'Windows Remote Management' }, callback=join_format_2, name="run_supplied_command")

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