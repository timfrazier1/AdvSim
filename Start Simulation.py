"""
"""

import phantom.rules as phantom
import json
from datetime import datetime, timedelta

def on_start(container):
    phantom.debug('on_start() called')
    
    # call 'run_script_1' block
    run_script_1(container=container)

    return

def run_script_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('run_script_1() called')

    # collect data for 'run_script_1' call

    parameters = []
    
    # build parameters list for 'run_script_1' call
    parameters.append({
        'ip_hostname': "172.31.76.156",
        'script_file': "",
        'script_str': "eventcreate /id 999 /D \"started\" /T INFORMATION /L application",
        'parser': "",
        'async': "",
        'command_id': "",
        'shell_id': "",
    })

    phantom.act("run script", parameters=parameters, app={ "name": 'Windows Remote Management' }, callback=playbook_local_Atomic_Registry_Run_Keys_1, name="run_script_1", parent_action=action)

    return

def playbook_local_Atomic_Registry_Run_Keys_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('playbook_local_Atomic_Registry_Run_Keys_1() called')
    
    # call playbook "local/Atomic - Registry Run Keys", returns the playbook_run_id
    playbook_run_id = phantom.playbook("local/Atomic - Registry Run Keys", container)

    run_script_2(container=container)

    return

def run_script_2(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('run_script_2() called')
    
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'run_script_2' call

    parameters = []
    
    # build parameters list for 'run_script_2' call
    parameters.append({
        'ip_hostname': "172.31.76.156",
        'script_file': "",
        'script_str': "eventcreate /id 999 /D \"ended\" /T INFORMATION /L application",
        'parser': "",
        'async': "",
        'command_id': "",
        'shell_id': "",
    })

    phantom.act("run script", parameters=parameters, app={ "name": 'Windows Remote Management' }, name="run_script_2")

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