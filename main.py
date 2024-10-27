import sys
import ast
import google.generativeai as genai
import re
import configparser
import os
import time
from google.generativeai.types import HarmCategory, HarmBlockThreshold
import pyautogui
import subprocess
import tempfile
import base64
import platform
import argparse
import json
import autoit

config_file = 'config.ini'
config = None
unattended = False
preprompt = '''You are directly controlling a windows PC primarily using autoit and screenshots. 
I will reply back with the result of any commands that return a value, and you can use that to decide what commands to generate next. 
I will also send you a screenshot before each prompt, as well as OS details like installed apps and paths. 
If you need another screenshot at some step, just ask.
YOU MUST get the environment ready before running the generated commands.
You must understand where the elements are placed before executing them, for example, chrome.exe might not be in the environment, use all commands properly.
If you do not see the screenshot, please ask for it.
You must follow these steps:
First off, you get a base screenshot and OS details.
Then you do tasks based off that screenshot.
Then you must ask for another screenshot for the next step, you can't just assume the elements are in the same place.
You must decompose your steps into multiple messages, not just one, for each screenshot you ask, the next step begins an you'll be able to send back a chat.
YOU MUST USE SLEEP FUNCTION TO WAIT FOR ELEMENTS TO LOAD.
Output only the functions to run and nothing else. Don't set any variables. Don't use window handles. Don't comment anything.
You can't just assume the locations of the executables, if you want to run an executable, you should look at its path in the OS details, and if it doesn't exist there, search it but never assume the path nor hardcode it.
Here is an example to open notepad:
`Run('notepad.exe')
WinWaitActive('[CLASS:Notepad]','',3)
ControlSend('[CLASS:Notepad]','','[CLASS:Edit1]','hello world')`

Here are some other functions you can use:
* Send(keys) - Sends keystrokes to the active window (use sparingly).
* TakeScreenshot() - Takes a screenshot and sends it to you.
* GetOSDetails() - Returns details about the operating system, including installed apps and paths.
* GetInstalledApps() - Returns a list of installed apps on the system.
* Sleep(milliseconds) - Pauses the script for the specified number of milliseconds.

Now generate commands to'''

apiKeys = [
  "AI...",
]
currentApiKeyIndex = 0

# Safety settings
safety_settings = {
    HarmCategory.HARM_CATEGORY_HATE_SPEECH: HarmBlockThreshold.BLOCK_NONE,
    HarmCategory.HARM_CATEGORY_HARASSMENT: HarmBlockThreshold.BLOCK_NONE,
    HarmCategory.HARM_CATEGORY_SEXUALLY_EXPLICIT: HarmBlockThreshold.BLOCK_NONE,
    HarmCategory.HARM_CATEGORY_DANGEROUS_CONTENT: HarmBlockThreshold.BLOCK_NONE,
}

# Generation config
generation_config = {
    "temperature": 1,
    "top_p": 0.95,
    "top_k": 64,
    "max_output_tokens": 8192,
    "response_mime_type": "text/plain",
}

debugging = False
debug_file = "debug.log"


def getNextApiKey():
    global currentApiKeyIndex
    apiKey = apiKeys[currentApiKeyIndex]
    currentApiKeyIndex = (currentApiKeyIndex + 1) % len(apiKeys)
    return apiKey


def load_config():
    global config
    config = configparser.ConfigParser()
    config.read(config_file)
    controller_section = None
    if ('Controller' in config):
        controller_section = config['Controller']
    else:
        save_config()
        controller_section = config['Controller']
    if (controller_section):
        global unattended, preprompt
        unattended = controller_section.getboolean('Unattended')
        preprompt = controller_section.get('Preprompt')


def save_config():
    global config
    config['Controller'] = {
        'Unattended': unattended,
        'Preprompt': preprompt
    }
    with open(config_file, 'w') as configfile:
        config.write(configfile)


def extract_code_blocks(code_string):
    code_block_regex = r"```(?:\w+\n)?([\w\W]*?)```|`(?:\w+\n)?([\w\W]*?)`"
    matches = re.findall(code_block_regex, code_string)
    
    # Extract the content within the code blocks, handling both single and triple backticks
    extracted_code = []
    for match in matches:
        if match[0]:  # Triple backticks
            extracted_code.append(match[0].strip())
        elif match[1]:  # Single backticks
            extracted_code.append(match[1].strip())
    
    if extracted_code:
        return extracted_code  # Return all code blocks found
    else:
        return code_string


def correct_file_path(arg):
    if (not isinstance(arg, str)):
        return arg
    if arg.startswith("'\"") and arg.endswith("\"'"):
        arg = arg.replace("'\"", "'").replace("\"'", "'")
    if arg.startswith('"'):
        arg = arg.replace('"', "'")
    if arg.endswith('"'):
        arg = arg.replace('"', "'")
    drive, path = os.path.splitdrive(arg.replace("'", "").replace('"', ""))
    if (drive):
        if (os.path.exists(arg)):
            return arg
        elif ("\\" in arg and not "\\\\" in arg):
            arg = arg.replace("\\", "/")
            if (os.path.exists(arg)):
                return arg
    return arg


def extract_file_path(cmd_string):
    cmds = re.findall(r'\((.*?)\)', cmd_string)
    argsnew = []
    for args in cmds:
        arg_list = [correct_file_path(arg.strip()) for arg in args.split(',')]
        argsnew.append('(' + ', '.join(arg_list) + ')')
    cmd_string_new = re.sub(r'\((.*?)\)', lambda x: argsnew.pop(0), cmd_string)
    return cmd_string_new



def convert_function_call(cmd_string):
    cmd_string = extract_file_path(cmd_string)
    tree = ast.parse(cmd_string.strip())
    function_call = next(node for node in ast.walk(tree) if isinstance(node, ast.Expr) and isinstance(node.value, ast.Call))
    function_name = function_call.value.func.id
    func = None
    if(function_name == 'Sleep'):
        func = time.sleep
    elif (function_name == 'Send'):
        func = pyautogui.write
    elif(function_name == 'TakeScreenshot'):
        func = take_screenshot
    elif(function_name == 'GetOSDetails'):
        func = get_os_details
    elif(function_name == 'GetInstalledApps'):
        func = get_installed_apps
    else:
        func = getattr(autoit, function_name)
    if func:
        args = [ast.literal_eval(arg) for arg in function_call.value.args]
        if(function_name == 'Sleep'):
            args[0] = args[0] / 1000
        try:
            funcResult = func(*args)
            return funcResult
        except Exception as e:
            errorMsg = "Call to " + function_name + " with arguments " + ",".join(str(x) for x in args) + " returned error: " + str(e)
            print(errorMsg)
            return errorMsg
    else:
        raise ValueError("Invalid function name: " + function_name)


def remove_variable_assignment(text):
    if not isinstance(text, str):
        return None  # Handle cases where text is not a string
    
    lines = text.split("\n")
    functions = []
    for line in lines:
        match = re.search(r'(\b\w+\(.*?\))', line)
        if match:
            functions.append(match.group(1).strip())
        else:
            functions.append(line)
    return functions


def execute_commands(cmds_list):
    if not isinstance(cmds_list, list):
        return None  # Handle cases where cmds_list is not a list

    funcData = []
    for cmd_string in cmds_list: # Iterate through the list of commands
        commands = remove_variable_assignment(cmd_string)
        if commands is None:
            return None

        for cmd in commands:
            returnData = convert_function_call(cmd)
            if returnData is not None:  # Check for None before converting to string
                funcData.append('Call to ' + cmd + ' returned: ' + str(returnData))
    if (len(funcData) > 0):
        return "\n".join(funcData) + "\nWhat function do you want to execute next?"
    else:
        return None


def take_screenshot():
    with tempfile.NamedTemporaryFile(suffix=".png", delete=False) as tmpfile:
        pyautogui.screenshot().save(tmpfile.name)
        with open(tmpfile.name, "rb") as f:
            encoded_string = base64.b64encode(f.read()).decode("utf-8")
            return f"data:image/png;base64,{encoded_string}"


def get_os_details():
    os_info = {
        "OS": os.name,
        "Platform": sys.platform,
        "Release": platform.release(),
        "Version": platform.version(),
        "Architecture": platform.machine(),
        "CPU Count": os.cpu_count(),
        "Installed Apps": get_installed_apps(),
        "Environment Variables": dict(os.environ),
    }
    return os_info


def get_installed_apps():
    if os.name == 'nt':
        data = subprocess.check_output(['wmic', 'product', 'get', 'name'])
        installed_apps = [line.decode('utf-8').strip() for line in data.splitlines() if line.decode('utf-8').strip()]
        return installed_apps[1:]  # Remove the header row
    elif os.name == 'posix':
        # Add logic to get installed apps on Linux/macOS if needed
        return []


def getCmd(model, chat_session, prompt, reply=False):
    screenshot = take_screenshot()
    os_details = get_os_details()

    if (reply):
        request_message = f"```\nScreenshot: {screenshot}\nOS Details: {os_details}\n```\n{prompt}"
    else:
        request_message = f"```\nScreenshot: {screenshot}\nOS Details: {os_details}\n```\n{preprompt} {prompt}"

    response = chat_session.send_message(request_message)
    chatResult = response.text

    if debugging:
        log_debug_info("Request", request_message, response)

    if chatResult:
        if hasattr(chatResult, '__len__') and (not isinstance(chatResult, str)):
            chatResult = str(chatResult[0])
        chatResult = extract_code_blocks(chatResult)
        if (not unattended):
            print('Going to execute:')
            if isinstance(chatResult, list):
                commands = []
                for code_block in chatResult:
                    commands.extend(remove_variable_assignment(code_block))
            else:
                commands = remove_variable_assignment(chatResult)
            if commands is not None:
                for cmd in commands:
                    print(cmd)
            else:
                print("No valid commands found in the response.")
                return

            confirmation = input("\nProceed? (y/n): ")
            if confirmation.lower() != "y":
                print("Operation cancelled.")
                return

        cmdResult = execute_commands(chatResult)
        if cmdResult:
            print(cmdResult)

        # Continue the conversation in the same session
        getCmd(model, chat_session, cmdResult, True) 


def log_debug_info(type, request_message, response):
    with open(debug_file, "a") as f:
        debug_info = {
            "type": type,
            "request": request_message,
            "response": response.text,
            "timestamp": time.time()
        }
        f.write(json.dumps(debug_info) + "\n")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Process some integers.')
    parser.add_argument('--debugging', action='store_true', help='enable debugging and save requests/responses')
    parser.add_argument('task', nargs='?', default=None, help='The task to perform') 
    args = parser.parse_args()

    debugging = args.debugging
    load_config()

    cmd_string = args.task
    if cmd_string is None:
        cmd_string = input("Enter a task: ")

    genai.configure(api_key=getNextApiKey())

    # Create the model
    model = genai.GenerativeModel(
        model_name="gemini-1.5-pro-002",
        generation_config=generation_config,
        safety_settings=safety_settings
    )

    chat_session = model.start_chat(
        history=[
        ]
    )
    getCmd(model, chat_session, cmd_string)
