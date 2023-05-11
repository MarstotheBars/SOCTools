# THE MAIN BREAD AND BUTTER OF THE SCRIPT. THIS IS FOR THE GUI FUNCTION
import tkinter as tk
from tkinter import ttk  # IMPORTS TTK FUNCTION
from tkinter import scrolledtext  # IMPORTS SCROLED TEXT FUNCTION
import webbrowser  # THIS IS FOR OPENING YOUR MAIN WEB BROWSER FOR TEAMS
import subprocess  # THIS IS FOR RUNNING IN-LINE CLI COMMANDS INTO THE TKINTER GUI
import re  # FOR REGEX ON THE EDR QUERY TAB
import codecs  # FOR UTILIZING CODECS FUNCTION FOR BOOLEAN. NEEDED TO PARSE RTF FILES IN FILE PATH
import requests  # FOR UTILIZING REQUESTS LIBRARY FOR API CALLS AND JSON
import pymsteams  # FOR UTILIZING TEAMS WEBHOOK
import configparser  # FOR STORING CREDENTIALS

# READS CREDENTIAL SECTION OF CONFIG FOR USERNAME AND PASSWORD. KEEP THE INI FILE SECURE.

config = configparser.ConfigParser()
config.read('config.ini')

username = config.get('credentials', 'username')
password = config.get('credentials', 'password')

# A NOTE ABOUT IMPORTS. ALL IMPORTS ARE NATIVE TO PYTHON BESIDES PYMSTEAMS
# LOOK UP A PYM STEAMS MODULE INSTALLATION GUIDE. USUALLY ONLY NEED TO
# pip3 install pymsteams

# CREATE MAIN WINDOW AND ALL THE TABS ASSOCIATED
root = tk.Tk()
root.title("Template and Tool Manager")
tabControl = ttk.Notebook(root)

welcometab = ttk.Frame(tabControl)
tab1 = ttk.Frame(tabControl)
tab2 = ttk.Frame(tabControl)
tab3 = ttk.Frame(tabControl)
tooltab = ttk.Frame(tabControl)
querytab = ttk.Frame(tabControl)
siemalert = ttk.Frame(tabControl)

# GENERATE ALL TABS FOR SPECIFIC FUNCTIONS
tabControl.add(welcometab, text='Resources and Info')
tabControl.add(tab1, text='Exception Case')
tabControl.add(tab2, text='Unapproved Application')
tabControl.add(tab3, text='Pending Approval')
tabControl.add(tooltab, text='CLI Tools')
tabControl.add(querytab, text='EDR Query Maker')

# SIEM ALERT TAB AND SUB NOTEBOOK DEFINED
tabControl.add(siemalert, text='SIEM Alert')
sub_notebook = ttk.Notebook(siemalert)
sub_notebook.grid()

tabControl.pack(expand=1, fill="both")

# DEFINE WELCOME WIDGET
text_widget = tk.Text(welcometab)

# WELCOME WIDGET TEXT
text_widget.insert(tk.END, "Hello, World!")

# PACK THE TEXT WIDGET TO THE WINDOW
text_widget.grid(column=5, row=6)


def open_ticket_page():
    webbrowser.open(
        "https://sampleurl.com")


# THIS IS THE BUTTON THAT OPENS THE AUTOTASK TAB IN THE WEB BROWSER
button_open_ticket_page = ttk.Button(
    welcometab, text="Create Ticket", command=open_ticket_page)
button_open_ticket_page.grid(column=0, row=4)


def open_abuseipdb():
    webbrowser.open(
        "https://www.abuseipdb.com/")


# THIS IS THE BUTTON THAT OPENS THE AUTOTASK TAB IN THE WEB BROWSER
button_open_abuseipdb = ttk.Button(
    welcometab, text="AbuseIPDB", command=open_abuseipdb)
button_open_abuseipdb.grid(column=1, row=4)


def open_alienvault():
    webbrowser.open(
        "https://otx.alienvault.com/")


# THIS IS THE BUTTON THAT OPENS THE AUTOTASK TAB IN THE WEB BROWSER
button_open_alienvault = ttk.Button(
    welcometab, text="Alienvault OTX", command=open_alienvault)
button_open_alienvault.grid(column=2, row=4)


def open_virustotal():
    webbrowser.open(
        "https://www.virustotal.com/gui/home/upload")


# THIS IS THE BUTTON THAT OPENS THE AUTOTASK TAB IN THE WEB BROWSER
button_open_virustotal = ttk.Button(
    welcometab, text="Virus Total", command=open_virustotal)
button_open_virustotal.grid(column=3, row=4)


def open_anyrun():
    webbrowser.open(
        "https://any.run/")


# THIS IS THE BUTTON THAT OPENS THE AUTOTASK TAB IN THE WEB BROWSER
button_open_anyrun = ttk.Button(
    welcometab, text="Any.run", command=open_anyrun)
button_open_anyrun.grid(column=4, row=4)


def open_joesandbox():
    webbrowser.open(
        "https://www.joesandbox.com/#windows")


# THIS IS THE BUTTON THAT OPENS THE AUTOTASK TAB IN THE WEB BROWSER
button_open_joesandbox = ttk.Button(
    welcometab, text="JoeSandbox", command=open_joesandbox)
button_open_joesandbox.grid(column=5, row=4)


def open_fortiguard():
    webbrowser.open(
        "https://www.fortiguard.com/")


# THIS IS THE BUTTON THAT OPENS THE AUTOTASK TAB IN THE WEB BROWSER
button_open_fortiguard = ttk.Button(
    welcometab, text="Fortiguard", command=open_fortiguard)
button_open_anyrun.grid(column=6, row=4)


def open_urlscan():
    webbrowser.open(
        "https://urlscan.io/")


# THIS IS THE BUTTON THAT OPENS THE AUTOTASK TAB IN THE WEB BROWSER
button_open_urlscan = ttk.Button(
    welcometab, text="URLScan", command=open_urlscan)
button_open_urlscan.grid(column=7, row=4)


def open_dllfiledatabase():
    webbrowser.open(
        "https://dll.website/")


# THIS IS THE BUTTON THAT OPENS THE AUTOTASK TAB IN THE WEB BROWSER
button_open_dllfiledatabase = ttk.Button(
    welcometab, text="DLL Database", command=open_dllfiledatabase)
button_open_dllfiledatabase.grid(column=8, row=4)


def open_talos():
    webbrowser.open(
        "https://talosintelligence.com")


# THIS IS THE BUTTON THAT OPENS THE AUTOTASK TAB IN THE WEB BROWSER
button_open_talos = ttk.Button(
    welcometab, text="Talos", command=open_talos)
button_open_talos.grid(column=9, row=4)


def open_mitre_attack():
    webbrowser.open(
        "https://attack.mitre.org/")


# THIS IS THE BUTTON THAT OPENS THE AUTOTASK TAB IN THE WEB BROWSER
button_open_mitre_attack = ttk.Button(
    welcometab, text="ATT&CK", command=open_mitre_attack)
button_open_mitre_attack.grid(column=10, row=4)


def open_mitre_defend():
    webbrowser.open(
        "https://d3fend.mitre.org/")


# THIS IS THE BUTTON THAT OPENS THE AUTOTASK TAB IN THE WEB BROWSER
button_open_mitre_defend = ttk.Button(
    welcometab, text="D3FEND", command=open_mitre_defend)
button_open_mitre_defend.grid(column=11, row=4)


# ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
# ALL FUNCTIONS ABOVE THIS POINT ARE FOR THE WELCOME TAB
#
# ALL FUNCTIONS BELOW THIS POINT ARE FOR CASE EXCEPTION TAB
# VVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVV


# DEFINE THE FUNCTIONS FOR APPROVED APPLICATION SEND REQUEST FUNCTION WHIH IS AN API CALL

def send_exception_request():

    # GET INPUT VALUES FOR CASE EXCEPTION TAB
    event_ids = event_ids_field.get()
    event_description = event_description_field.get(1.0, tk.END)
    apply_exception_on = apply_exception_on_field.get()
    apply_exception_on_current_or_any = apply_exception_on_current_or_any_field.get()
    when_created_by = when_created_by_field.get()
    apply_exception_on_when_created_by = apply_exception_on_when_created_by_field.get()

    # EDR API ENDPOINT INFORMATION. DEFINED PARAMETERS TO SEARCH ALL ORGANIZATIONS FOR EVENT ID
    api_endpoint = "https://apiendpoint.com"
    params = {
        "Organization": "All Organizations",
        "eventIds": event_ids,
    }

    # USERNAME AND PASSWORD FOR BASIC API AUTHENTICATION
    username = username
    password = password

    # SET API HEADERS
    headers = {
        'Accept': 'application/json',
        'Content-Type': 'application/json',
    }

    # API REQUEST SEND PARAMETERS WITH BASIC AUTHENTICATION
    response = requests.get(api_endpoint, auth=(
        username, password), headers=headers, params=params)

    # CHECKS STATUS CODE AND PERFORMS ACTIONS BASED ON CODE RECEIVED FROM API CALL
    if response.status_code == 200:
        # EXTRACTS SPECIFIC API KEYS WITH THE RETURNED CALL
        data = response.json()
        for event in data:
            process = event['process']
            organization = event['organization']
            eventId = event['eventId']
            exception_rules = event['rules']
            exception_formatted_rules = " ".join(exception_rules)
            collectors = event['collectors']
            for collector in collectors:
                device = collector['device']
                # FORMATS THE OUTPUT AND INSERTS INTO THE TEMPLATE BELOW
                output1 = f"{process} | {organization} | Event # {eventId}\n\n"
                output1 += f"This event was triggered due to a \"{exception_formatted_rules}\" on host: {device}\n\n"
                output1 += f"{event_description}\n\n"
                output1 += f"There appears to be nothing suspicious about this behavior, nor does there appear to be anything suspicious in the process path or command line arguments.\n\n"
                output1 += f"If there are no objections, I will create an exception for \"{apply_exception_on}\" on the {apply_exception_on_current_or_any} when created by \"{when_created_by}\" on the {apply_exception_on_when_created_by} for the rule: \"{exception_formatted_rules}\""
                # OUTPUT IS INSERTED INTO THE OUTPUT TEXT WIDGET
                # CLEARS THE VALUE OF OUTPUT BOX ONCE THE CLEAR BUTTON IS CALLED. THIS IS HERE BECAUSE OUTPUT_TEXT ISN'T A GLOBAL VARIABLE
                output_text = scrolledtext.ScrolledText(
                    tab1, width=75, height=20)
                output_text.delete(1.0, tk.END)
                output_text.insert(tk.END, output1 + "\n")
                output_text.grid(column=2, row=1)
                # Send output_text to send_output_to_teams variable
                send_output_to_teams(output_text)
    else:
        # ERROR MESSAGE IS RESPONSE IS ANYTHING OTHER THAN 200 CODE
        output_text.insert(
            tk.END, "Something went wrong. Status code: {}".format(response.status_code))

# DEFINE THE SEND OUTPUT TO TEAMS FUNCTION. THIS NEEDS TO BE TESTED


def send_output_to_teams(output_text):
    # SEND MESSAGE TO TEAMS
    myTeamsMessage = pymsteams.connectorcard(
        "https://webhook.com")
    myTeamsMessage.text(output_text.get(1.0, tk.END))
    myTeamsMessage.send()


# LABEL AND FIELD FOR EVENT IDS
event_ids_label = tk.Label(
    tab1, text="Enter the event IDs separated by commas:")
event_ids_field = tk.Entry(tab1)

# LABEL AND FIELD FOR EVENT DESCRIPTION FOR CASE EXCEPTION
event_description_label = tk.Label(tab1, text="Enter the event description:")
event_description_field = tk.Text(tab1, height=25, width=50)

# LABEL AND FIELD FOR APPLY EXCEPTION ON FOR CASE EXCEPTION
apply_exception_on_label = tk.Label(
    tab1, text="Apply Eception On: ")
apply_exception_on_field = tk.Entry(tab1)

# LABEL AND FIELD FOR CURRENT OR ANY PATH FOR CASE EXCEPTION
apply_exception_on_current_or_any_label = tk.Label(
    tab1, text="Current or Any path")
apply_exception_on_current_or_any_field = tk.Entry(tab1)

# LABEL AND FIELD FOR WHEN CREATED BY FOR CASE EXCEPTION
when_created_by_label = tk.Label(
    tab1, text="When Created By:")
when_created_by_field = tk.Entry(tab1)

# LABEL AND FIELD FOR CURRENT OR ANY PATH FOR WHEN CREATED BY FOR CASE EXCEPTION
apply_exception_on_when_created_by_label = tk.Label(
    tab1, text="Current or Any path:")
apply_exception_on_when_created_by_field = tk.Entry(tab1)

# CREATE A BUTTON FOR SEND REQUEST FOR CASE EXCEPTION FOR API CALL
request_button = tk.Button(tab1, text="Send Request",
                           command=send_exception_request)

# CREATE A BUTTON FOR SENDING THE OUTPUT TO TEAMS.
send_output_to_teams_button = tk.Button(
    tab1, text="Send to Teams", command=send_output_to_teams)

# .GRID GEOMETRY MANAGER FOR CASE EXCEPTION TAB
event_ids_label.grid(row=0, column=0)
event_ids_field.grid(row=0, column=1)
event_description_label.grid(row=1, column=0)
event_description_field.grid(row=1, column=1)
apply_exception_on_label.grid(row=2, column=0)
apply_exception_on_field.grid(row=2, column=1)
apply_exception_on_current_or_any_label.grid(row=3, column=0)
apply_exception_on_current_or_any_field.grid(row=3, column=1)
when_created_by_label.grid(row=4, column=0)
when_created_by_field.grid(row=4, column=1)
apply_exception_on_when_created_by_label.grid(row=5, column=0)
apply_exception_on_when_created_by_field.grid(row=5, column=1)
send_output_to_teams_button.grid(row=7, column=1)
request_button.grid(row=6, column=1)


# CLEAR FUNCTIONS DEFINITION FOR CASE EXCEPTION TAB


def clear_fields():
    event_ids_field.delete(0, "end")
    event_description_field.delete("1.0", "end")
    apply_exception_on_field.delete(0, "end")
    apply_exception_on_current_or_any_field.delete(0, "end")
    when_created_by_field.delete(0, "end")
    apply_exception_on_when_created_by_field.delete(0, "end")


# CLEAR TEXT FOR CASE EXEPTION BUTTON THAT UTILIZES CLEAR_FIELDS FUNCTION
clear_button = ttk.Button(tab1, text="Clear", command=clear_fields)
clear_button.grid(column=1, row=11, padx=30, pady=15)

# ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
# ALL FUNCTIONS ABOVE THIS POINT ARE FOR CASE EXCEPTION TAB
#
# ALL FUNCTIONS BELOW THIS POINT ARE FOR UNAPPROVED APPLICATION TAB
# VVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVV


# CREATE TEMPLATES FOR UNAPPROVED APP AND PENDING APPROVAL. THEN DEFINE WHAT HAPPENS WHEN GENERATE_OUTPUT BUTTON IS PRESSED
def display_event_info(eventId_unapproved, output2, counter,
                       process_unapproved, organization_unapproved, event_handle2, row_counter):
    def callback(event):
        # CREATE NEW WINDOW
        event_info_window = tk.Tk()
        event_info_window.title("Event Information")
        # CREATE LABEL FOR OUTPUT2 FROM PREVIOUS EVENT
        historical_event = tk.Label(event_info_window, text=output2)
        historical_event.grid()

        # SHOW WINDOW AFTER THE EVENT IS CLICKED
        event_info_window.mainloop()

    # CREATE BUTTON WITH EVENT_ID AS LABEL, AND PASS TAB2 AS PARENT WIDGET
    historical_button = tk.Button(
        tab2, text=f"{process_unapproved} | {organization_unapproved} | {eventId_unapproved}")
    # BIND CALLBACK TO <Button-1> EVENT
    historical_button.bind("<Button-1>", callback)
    # PLACE BUTTON IN GUI USING GRID WITH COLUMN OPTION
    historical_button.grid(row=row_counter, column=counter)
    print(row_counter)
    print(counter)

# DEFINE GLOBAL COUNTER NUMBERS TO INCRIMENT ROW +1 FOR EVERY +3 OF THE COLUMN CREATING A GRID.


counter = -1
row_counter = 12


def send_unapproved_request():
    global counter
    global row_counter
    counter += 1
    if counter >= 3:
        counter = 0
        row_counter += 1

    # GET INPUT VALUES FOR UNAPPROVED APPLICATION TAB
    event_ids = event_ids_unapproved_field.get()
    event_description2_contents = event_description2.get("1.0", "end")
    analysis_performed_by2 = entry_analysis_performed_by2.get()
    event_handle2 = entry_event_handle2.get()

    # EDR API ENDPOINT INFORMATION. DEFINED PARAMETERS TO SEARCH ALL ORGANIZATIONS FOR EVENT ID
    api_endpoint = "https://apiendpoint.com"
    params = {
        "Organization": "All Organizations",
        "eventIds": event_ids,
    }

    # USERNAME AND PASSWORD FOR BASIC API AUTHENTICATION
    username = username
    password = password

    # SET API HEADERS
    headers = {
        'Accept': 'application/json',
        'Content-Type': 'application/json',
    }

    # API REQUEST SEND PARAMETERS WITH BASIC AUTHENTICATION
    response = requests.get(api_endpoint, auth=(
        username, password), headers=headers, params=params)

    # CHECKS STATUS CODE AND PERFORMS ACTIONS BASED ON CODE RECEIVED FROM API CALL
    if response.status_code == 200:
        # EXTRACTS SPECIFIC API KEYS WITH THE RETURNED CALL
        data = response.json()
        for event in data:
            process_unapproved = event['process']
            organization_unapproved = event['organization']
            eventId_unapproved = event['eventId']
            rules_unapproved = event['rules']
            formatted_rules = " ".join(rules_unapproved)
            collectors = event['collectors']
            for collector in collectors:
                device_unapproved = collector['device']
                # FORMATS THE OUTPUT AND INSERTS INTO THE TEMPLATE BELOW
                output2 = f"{process_unapproved} | {organization_unapproved} | Event # {eventId_unapproved} | {analysis_performed_by2}\n"
                output2 += "\n"
                output2 += f"This event was triggered due to the broken rule: \"{formatted_rules}\" on the host:{device_unapproved} \n\n"
                output2 += "\n"
                output2 += f"{event_description2_contents}"
                output2 += "\n"
                output2 += f"MSP has confirmed, this is an unapproved application for {organization_unapproved} and has been removed from the endpoint. This Event will be handled as {event_handle2}"
                # OUTPUT IS INSERTED INTO THE OUTPUT TEXT WIDGET
                # CLEARS THE VALUE OF OUTPUT BOX ONCE THE CLEAR BUTTON IS CALLED. THIS IS HERE BECAUSE OUTPUT_TEXT ISN'T A GLOBAL VARIABLE
                output_unapproved_text = scrolledtext.ScrolledText(
                    tab2, width=75, height=20)
                output_unapproved_text.delete(1.0, tk.END)
                output_unapproved_text.insert(tk.END, output2 + "\n")
                output_unapproved_text.grid(column=2, row=6)
                # SENDS VARIABLES TO DISPLAY_EVENT_INFO FUNCTION WHICH IS A HISTORIAN OF EVENTS USED. DELETES AFTER CLOSING APP W/ NO DATABASE
                display_event_info(eventId_unapproved, output2, counter,
                                   process_unapproved, organization_unapproved, event_handle2, row_counter)
                # IS CALLED ONCE SEND_REQUEST BUTTON IS PRESSED TO SHOW FORMATTING
                queue_label = tk.Label(tab2, text="Event ID queue:")
                queue_label.grid(row=11, column=1)

    else:
        # ERROR MESSAGE IS RESPONSE IS ANYTHING OTHER THAN 200 CODE
        output_unapproved_text.insert(
            tk.END, "Something went wrong. Status code: {}".format(response.status_code))


# UNAPPROVED APPLICATION WIDGETS (TAB2)
# INPUT EVENT NUMBER INTO UNAPPROVED APPLICATION TAB USING GRID GEOMETY MANAGER


event_ids_unapproved_label = tk.Label(
    tab2, text="Enter the event IDs separated by commas:")
event_ids_unapproved_field = tk.Entry(tab2)
event_ids_unapproved_label.grid(row=0, column=0)
event_ids_unapproved_field.grid(row=0, column=1)


# INPUT ANALYSIS PERFORMED INTO UNAPPROVED APPLICATION TAB BY USING GRID GEOMETRY MANAGER
ttk.Label(tab2, text="Analysis Performed By:").grid(
    column=0, row=3, padx=30, pady=30)
entry_analysis_performed_by2 = tk.Entry(tab2)
entry_analysis_performed_by2.grid(column=1, row=3)

# INPUT EVENT DESCRIPTION INTO UNAPPROVED APPLICATION TAB USING GRID GEOMETRY MANAGER
ttk.Label(tab2, text="Event Description:").grid(column=0, row=6)
event_description2 = tk.Text(tab2, height=10, width=50)
event_description2.grid(column=1, row=6, pady=15)

# INPUT HANDLING STATUS INTO UNAPPROVED APPLICATION TAB USING GRID GEOMETRY MANAGER
ttk.Label(tab2, text="How are you handling this event? Inconclusive/Suspicious/Malicious/Safe:").grid(column=0, row=8)
entry_event_handle2 = tk.Entry(tab2)
entry_event_handle2.grid(column=1, row=8)

# CREATE A BUTTON FOR SEND REQUEST FOR CASE EXCEPTION FOR API CALL
request_unapproved_button = tk.Button(
    tab2, text="Send Request", command=send_unapproved_request)
request_unapproved_button.grid(row=9, column=1)

# CLEAR FIELDS FUNCTION FOR UNAPPROVED APPLICATION(TAB2)


def clear_unapproved_fields():
    event_ids_unapproved_field.delete(0, "end")
    event_description2.delete("1.0", "end")
    entry_analysis_performed_by2.delete(0, "end")
    entry_event_handle2.delete(0, "end")


# CLEAR FIELDS FOR UNAPPROVED APPLICATION AND MAPPED TO CLEAR_FIELDS DEFINITION
clear_unapproved_button = ttk.Button(
    tab2, text="Clear", command=clear_unapproved_fields)
clear_unapproved_button.grid(column=1, row=10, padx=30)


# ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
# ALL FUNCTIONS ABOVE THIS POINT ARE FOR UNAPPROVED APPLICATION TAB
#
# ALL FUNCTIONS BELOW THIS POINT ARE FOR PENDING APPROVAL TAB
# VVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVV

# DEFINE FUNCTION FOR GENERATING OUTPUT BUTTON ON THE PENDING APPROVAL TAB


def generate_pending_output(event_description3):

    # ENTRY VALUES FOR PENDING APPROVAL TAB
    it_team_name = entry_it_team_name.get()
    application_name = entry_application_name.get()
    rule_broken3 = entry_rule_broken3.get()
    time_month_date_year = entry_time_month_date_year.get()
    event_description3_contents = event_description3.get("1.0", "end")
    organization3 = entry_organization3.get()
    host_name3 = entry_host_name3.get()
    user = entry_user.get()
    analysis_performed_by3 = entry_analysis_performed_by3.get()
    file_path = entry_file_path.get()

    # PENDING APPROVAL TEMPLATE
    output3 = f"Dear {it_team_name}\n"
    output3 += "\n"
    output3 += f"The application: \"{application_name}\" triggered the rule: \"{rule_broken3}\" at {time_month_date_year}"
    output3 += "\n\n"
    output3 += f"{event_description3_contents}"
    output3 += "\n"
    output3 += f"Is the application \"{application_name}\" approved for customer \"{organization3}\" on Host: \"{host_name3}\" for User: \"{user}\"\n?"
    output3 += f"If not, please remove the software in question. \n\n"
    output3 += "Thanks,"
    output3 += "\n\n"
    output3 += f"{analysis_performed_by3}\n\n"
    output3 += f"{file_path}"

    # OUTPUT BOX DISPLAYED AFTER HITTING GENERATE OUTPUT BUTTON ON PENDING APPROVAL TAB
    output_text3 = scrolledtext.ScrolledText(tab3, width=75, height=20)
    output_text3.insert("insert", output3)
    output_text3.grid(column=2, row=6)


# PENDING APPROVAL (TAB3) WIDGETS
# INPUT IT TEAM NAME INTO PENDING APPROVAL TAB USING GRID GEOMETRY MANAGER
ttk.Label(tab3, text="IT Team Name:").grid(column=0, row=0)
entry_it_team_name = ttk.Entry(tab3)
entry_it_team_name.grid(column=1, row=0)

# INPUT APPLICATION NAME INTO PENDING APPROVAL TAB USING GRID GEOMETRY MANAGER
ttk.Label(tab3, text="Application name:").grid(column=0, row=1)
entry_application_name = ttk.Entry(tab3)
entry_application_name.grid(column=1, row=1)

# INPUT RULE BROKEN INTO PENDING APPROVAL TAB USING GRID GEOMETRY MANAGER
ttk.Label(tab3, text="Rule Broken:").grid(column=0, row=2)
entry_rule_broken3 = ttk.Entry(tab3)
entry_rule_broken3.grid(column=1, row=2)

# INPUT TIME MONTH DATE YEAR INTO PENDING APPROVAL TAB USING GRID GEOMETRY MANAGER
ttk.Label(tab3, text="Time, Month, Date, Year:").grid(column=0, row=3)
entry_time_month_date_year = ttk.Entry(tab3)
entry_time_month_date_year.grid(column=1, row=3)

#  INPUT EVENT DESCRIPTION INFORMATION INTO PENDING APPROVAL TAB USING GEOMETRY GRID MANAGER
ttk.Label(tab3, text="Event Description:").grid(column=0, row=6)
event_description3 = tk.Text(tab3, height=10, width=50)
event_description3.grid(column=1, row=6, padx=30, pady=15)

# INPUT ORGANIZATION INFORMATION INTO PENDING APPROVAL TAB USING GEOMETRY GRID MANAGER
ttk.Label(tab3, text="Organization:").grid(column=0, row=7)
entry_organization3 = ttk.Entry(tab3)
entry_organization3.grid(column=1, row=7)

# INPUT HOST NAME INFORMATION INTO PENDING APPROVAL TAB USING GEOMETRY GRID MANAGER
ttk.Label(tab3, text="Host Name").grid(column=0, row=8)
entry_host_name3 = ttk.Entry(tab3)
entry_host_name3.grid(column=1, row=8)

# INPUT USER INFORMATION INTO PENDING APPROVAL TAB USING GEOMETRY GRID MANAGER
ttk.Label(tab3, text="User").grid(column=0, row=9)
entry_user = ttk.Entry(tab3)
entry_user.grid(column=1, row=9)

# INPUT ANALYSIS PERFORMED BY INFORMATION INTO PENDING APPROVAL TAB USING GEOMETRY GRID MANAGER
ttk.Label(tab3, text="Analysis performed by:").grid(column=0, row=10)
entry_analysis_performed_by3 = ttk.Entry(tab3)
entry_analysis_performed_by3.grid(column=1, row=10)

# INPUT FILE PATH INFORMATION INTO PENDING APPROVAL TAB USING GEOMETRY GRID MANAGER
ttk.Label(tab3, text="File Path:").grid(column=0, row=11)
entry_file_path = ttk.Entry(tab3)
entry_file_path.grid(column=1, row=11)

# DEFINE THE OPEN_WEBPAGE WIDGET. THIS TAKES YOU STRAIGHT TO AUTO TASK NEW TICKET FUNCTION WITHIN THE APPLCIATION.

# NAVIGATES TO AUTO TASK. DOESN'T OPEN TICKET AUTOMATICALLY.


def open_webpage():
    webbrowser.open(
        "https://ticketcompany.com")


# THIS IS THE BUTTON THAT OPENS THE AUTOTASK TAB IN THE WEB BROWSER
button_open_auto_task = ttk.Button(
    tab3, text="Create Ticket", command=open_webpage)
button_open_auto_task.grid(column=0, row=13)

# DEFINE THE CLEAR FIELDS FUNCTION FOR PENDING APPROVAL TAB


def clear_fields():
    entry_application_name.delete(0, "end")
    entry_it_team_name.delete(0, "end")
    entry_rule_broken3.delete(0, "end")
    entry_organization3.delete(0, "end")
    entry_host_name3.delete(0, "end")
    entry_user.delete(0, "end")
    entry_analysis_performed_by3.delete(0, "end")
    entry_time_month_date_year.delete(0, "end")
    entry_file_path.delete(0, "end")
    event_description3.delete(1.0, "end")


# CLEAR FIELDS BUTTON THAT UTILIZES THE CLEAR_FIELDS FUNCTION DEFINED FOR PENDING APPROVAL
clear_button = ttk.Button(tab3, text="Clear", command=clear_fields)
clear_button.grid(column=1, row=12, padx=30, pady=30)

# PENDING APPROVAL GENERATE OUTPUT BUTTON
button_generate_output = ttk.Button(
    tab3, text="Generate Output", command=lambda: generate_pending_output(event_description3))
button_generate_output.grid(column=0, row=12)

# ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
# ALL FUNCTIONS ABOVE THIS POINT ARE FOR PENDING APPROVAL TAB
#
# ALL FUNCTIONS BELOW THIS POINT ARE FOR CLI COMMANDS TAB
# VVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVV

# LABEL AND ENTRY FUNCTION FOR THE TOOLTAB

domain_label = tk.Label(tooltab, text="Enter a domain:")
domain_entry = tk.Entry(tooltab)

# TOOLTAB FUNCTIONS DEFINED. WHOIS, NSLOOKUP, PING, CERTLOOKUP. THIS CAN BE EXPANDED ON AS EMPTY PLACEHOLDER BUTTONS ARE CREATED
# THESE FUNCTIONS WILL NOT WORK WITHOUT THE TERMINAL OPEN


def whois_lookup():
    domain = domain_entry.get()
    result = subprocess.run(["whois", domain], capture_output=True)
    output = result.stdout.decode()
    text_area.insert(tk.END, output)


def nslookup_lookup():
    domain = domain_entry.get()
    result = subprocess.run(["nslookup", domain], capture_output=True)
    output = result.stdout.decode()
    text_area.insert(tk.END, output)


def ping_lookup():
    domain = domain_entry.get()
    result = subprocess.run(["ping", "-c", "4", domain], capture_output=True)
    output = result.stdout.decode()
    text_area.insert(tk.END, output)


def cert_lookup():
    domain = domain_entry.get()
    result = subprocess.run(["openssl", "s_client", "-host", domain,
                             "-port", "443", "-prexit", "-showcerts"], stdout=subprocess.PIPE)
    output = result.stdout.decode()
    text_area.insert(tk.END, output)


def traceroute_lookup():
    domain = domain_entry.get()
    result = subprocess.run(["traceroute", domain, ], stdout=subprocess.PIPE)
    output = result.stdout.decode()
    text_area.insert(tk.END, output)

# TOOLTAB FRAME DEFINED AND PUT WITHIN THE MAIN TAB


new_frame = tk.Frame(tooltab)
new_frame.pack(side="top", fill="x")

# WHOIS PING AND NSLOOKUP FUNCTION BUTTONS DEFINED. THESE ARE PRESSABLE AND CAN PERFORM FUNCTION BASED ON ACTION DEFINED.
whois_button = tk.Button(new_frame, text="Whois Lookup", command=whois_lookup)
nslookup_button = tk.Button(
    new_frame, text="nslookup Lookup", command=nslookup_lookup)
ping_button = tk.Button(new_frame, text="Ping", command=ping_lookup)
cert_button = tk.Button(new_frame, text="Cert Lookup", command=cert_lookup)
traceroute_button = tk.Button(
    new_frame, text="Traceroute", command=traceroute_lookup)

# PACKED BUTTONS FOR THE CLI TOOLS
whois_button.pack(side="left", in_=new_frame)
nslookup_button.pack(side="left", in_=new_frame)
ping_button.pack(side="left", in_=new_frame)
cert_button.pack(side="left", in_=new_frame)
traceroute_button.pack(side="left", in_=new_frame)

# PLACEHOLDER BUTTONS FOR FUTURE USE.

domain_label.pack(side="top")
domain_entry.pack(side="top", fill="x", expand=True)

# IF THIS IS USED, MOVE IT TO THE BUTTONS DEFINED. PLACEHOLDERS
empty_button3 = tk.Button(new_frame, text="Placeholder")
empty_button4 = tk.Button(new_frame, text="Placeholder")
empty_button5 = tk.Button(new_frame, text="Placeholder")

# IF THIS IS USED, MOVE IT TO THE PACKED BUTTONS FOR CLI TOOLS. PLACEHOLDERS
empty_button3.pack(side="left", in_=new_frame)
empty_button4.pack(side="left", in_=new_frame)
empty_button5.pack(side="left", in_=new_frame)

# FRAME THAT WILL HOLD THE TEXT AREA THAT IS TO BE DEFINED BELOW
text_frame = tk.Frame(tooltab)
text_frame.pack(side="bottom", fill="both", expand=True)

# TEXT AREA PUT INSIDE THE FRAME DEFINED RIGHT ABOVE
text_area = tk.Text(text_frame)
text_area.pack(fill="both", expand=True)

# ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
# ALL FUNCTIONS ABOVE THIS POINT ARE FOR CLI COMMANDS TAB
#
# ALL FUNCTIONS BELOW THIS POINT ARE EDR QUERY TAB
# VVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVV

# DEFINED FUNCTIONS FOR QUERY TAB. THIS IS A WORK IN PROGRESS.

# SHA 256 DEFINITION


def is_sha256(string):
    # Check if the string is a Sha-256 hash by using a regular expression
    # to match the pattern of a Sha-256 hash (64 hexadecimal characters)
    return bool(re.match(r'^[a-fA-F0-9]{64}$', string))

# IP ADDRESS DEFINITION


def is_ip_address(string):
    # Check if the string is an IP address by using a regular expression
    # to match the pattern of an IP address (four groups of digits separated by dots)
    return bool(re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', string))

# DEFINE OPEN TARGET PATH FUNCTION


def process_file():
    # GET THE FILE PATH. FILE NEEDS TO BE IN DIRECTORY OF THE PYTHON SCRIPT. <----- WORK IN PROGRESS
    target_file_path = target_file_path_entry.get()

    # CLEARS OUTPUT OF THE QUERY
    output_query.delete('1.0', tk.END)

    # OPENS FILE IN UTF-8 ENCODING AND READS LINE BY LINE
    with codecs.open(target_file_path, 'r', 'utf-8') as f:
        # Read the file and process the contents
        contents = f.read()

    # INITIALIZES THE LIST TO STORE THE OUTPUT OF THE FUNCTION TO THEN DISPLAY TO THE OUTPUT BOX
    output = []

    # FUNCTION TO SPLIT LINE BY LINE
    lines = contents.splitlines()

    # ITERATES LINE BY LINE
    for line in lines:
        # STRIPS WHITE SPACE
        line = line.strip()

        # CHECKS THE TYPE FROM THE LINE WHETHER IP, FILE TYPE OR SHA256
        if is_sha256(line):
            output.append('Target.Hash.Sha256: ' + line)
        elif is_ip_address(line):
            output.append('RemoteIP: ' + line)
        else:
            output.append('Target.File.Name: ' + line)

    # COMBINES THE ELEMENTS WITH AN OR STATEMENT
    output_string = ' OR '.join(output)

    # OUTPUT STRING INPUTTED INTO THE OUTPUT TEXT WIDGET
    output_query.insert('1.0', output_string)

# DEFINES THE CLEAR OUTPUT FUNCTION


def clear_output():
    # Clear the output text widget
    output_query.delete('1.0', tk.END)

# CREATES THE BUTTON TO CLEAR THE OUTPUT FOR EDR QUERY


clearquery_button = tk.Button(querytab, text='Clear', command=clear_output)
clearquery_button.pack(side="bottom")


# CREATES A FRAME TO HOLD THE QUERY BUTTON AND INPUT FUNCTIONS
file_frame = tk.Frame(querytab)

# LABEL FOR FILE PATH ENTRY
target_file_path_label = tk.Label(file_frame, text='File path:')
target_file_path_label.pack(side='left')

# WIDGET FOR THE FILE PATH
target_file_path_entry = tk.Entry(file_frame)
target_file_path_entry.pack(side='left')

# BUTTON THAT PROCESSES THE FILE
process_button = tk.Button(file_frame, text='Process', command=process_file)
process_button.pack(side='left')

# PACKS THE FILE FRAME
file_frame.pack()

# TEXT WIDGET TO DISPLAY THE OUTPUT FROM QUERY
output_query = tk.Text(querytab)
output_query.pack()

# ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
# ALL FUNCTIONS ABOVE THIS POINT ARE FOR EDR QUERY FUNCTION
#
# ALL FUNCTIONS BELOW THIS POINT ARE FOR EMAIL VIRUS TEMPLATE
# VVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVV

# Create two tabs on the second notebook
siemalert_subtab1 = ttk.Frame(sub_notebook)
sub_notebook.add(siemalert_subtab1, text='MalFile Block')


def siem_malware_alert():

    # ENTRY VALUES FOR SIEM ALERT TAB
    incident_firewall_customer = entry_incident_firewall_customer.get()
    incident_location = entry_incident_location.get()
    incident_timestamp = entry_incident_timestamp.get()
    incident_source_ip = entry_incident_source_ip.get()
    incident_hostname = entry_incident_hostname.get()
    incident_malware_name = entry_incident_malware_name.get()
    incident_url = entry_incident_url.get()

    # DEFANG THE URL
    incident_url = re.sub(r'^https?://', 'hxxp://', incident_url)
    incident_url = re.sub(r'^http?://', 'hxxp://', incident_url)

    # REPLACE PERIODS WITH BRACKETS
    incident_url = incident_url.replace('.', '[.]')

    # SIEM ALERT TEMPLATE
    alert_output = f"Dear {incident_firewall_customer},\n"
    alert_output += "\n"
    alert_output += "Our firewall has detected and blocked an attempt to download a malicious file. Details can be seen below.\n"
    alert_output += "\n"
    alert_output += f"Incident Location => {incident_location}\n"
    alert_output += "\n"
    alert_output += f"Incident Timestamp => {incident_timestamp}\n"
    alert_output += "\n"
    alert_output += f"Incident Source (IP and Hostname) => {incident_source_ip} ({incident_hostname})\n"
    alert_output += "\n"
    alert_output += f"Incident Details or Malware Name => {incident_malware_name}\n"
    alert_output += "\n"
    alert_output += f"Incident URL => {incident_url}\n"
    alert_output += "\n"
    alert_output += "Company recommends that you consult with your IT Support to ensure all computers are up-to-date with the latest security patches and updates. We also recommend consulting with your IT Support to ensure all software is patched and updated as well.\n"
    alert_output += "\n"
    alert_output += "At your request, we can take the necessary steps to block this computer from your network, if needed.\n"
    alert_output += "\n"
    alert_output += "Thanks,\n\n"
    alert_output += "Company \n"
    alert_output += "Contact: security @ domain.com

    # OUTPUT BOX DISPLAYED AFTER HITTING GENERATE OUTPUT BUTTON ON SIEM ALERT TAB
    siem_alert_output = scrolledtext.ScrolledText(
        siemalert_subtab1, width=80, height=45)
    siem_alert_output.insert("insert", alert_output)
    siem_alert_output.grid(column=2, row=0, rowspan=12)


empty_box = scrolledtext.ScrolledText(
    siemalert_subtab1, width=75, height=45)
empty_box.grid(column=2, row=0, rowspan=12)

# SIEM ALERT WIDGETS
# INPUT IT TEAM NAME INTO SIEM ALERT TAB USING GRID GEOMETRY MANAGER
ttk.Label(siemalert_subtab1, text="Firewall POC or Team: ").grid(
    column=0, row=0)
entry_incident_firewall_customer = ttk.Entry(siemalert_subtab1)
entry_incident_firewall_customer.grid(column=1, row=0)

# INPUT APPLICATION NAME INTO SIEM ALERT TAB USING GRID GEOMETRY MANAGER
ttk.Label(siemalert_subtab1, text="Incident Location Name: ").grid(
    column=0, row=1)
entry_incident_location = ttk.Entry(siemalert_subtab1)
entry_incident_location.grid(column=1, row=1)

# INPUT RULE BROKEN INTO SIEM ALERT TAB USING GRID GEOMETRY MANAGER
ttk.Label(
    siemalert_subtab1, text="Incident Timestamp(XX:XX on MM/DD/YYYY)").grid(column=0, row=2)
entry_incident_timestamp = ttk.Entry(siemalert_subtab1)
entry_incident_timestamp.grid(column=1, row=2)

# INPUT TIME MONTH DATE YEAR INTO SIEM ALERT TAB USING GRID GEOMETRY MANAGER
ttk.Label(siemalert_subtab1, text="Source IP:").grid(column=0, row=3)
entry_incident_source_ip = ttk.Entry(siemalert_subtab1)
entry_incident_source_ip.grid(column=1, row=3)

#  INPUT EVENT DESCRIPTION INFORMATION INTO SIEM ALERT TAB USING GEOMETRY GRID MANAGER
ttk.Label(siemalert_subtab1, text="Target Hostname:").grid(column=0, row=6)
entry_incident_hostname = tk.Entry(siemalert_subtab1)
entry_incident_hostname.grid(column=1, row=6)

# INPUT ORGANIZATION INFORMATION INTO SIEM ALERT TAB USING GEOMETRY GRID MANAGER
ttk.Label(siemalert_subtab1, text="Fortiguard Malware Name:").grid(
    column=0, row=7)
entry_incident_malware_name = ttk.Entry(siemalert_subtab1)
entry_incident_malware_name.grid(column=1, row=7)

# INPUT HOST NAME INFORMATION INTO SIEM ALERT TAB USING GEOMETRY GRID MANAGER
ttk.Label(siemalert_subtab1, text="Remote URL: ").grid(column=0, row=8)
entry_incident_url = ttk.Entry(siemalert_subtab1)
entry_incident_url.grid(column=1, row=8)

# DEFINE THE CLEAR FIELDS FUNCTION FOR SIEM ALERT TAB


def clear_malfile_fields():
    entry_incident_firewall_customer.delete(0, "end")
    entry_incident_location.delete(0, "end")
    entry_incident_timestamp.delete(0, "end")
    entry_incident_source_ip.delete(0, "end")
    entry_incident_hostname.delete(0, "end")
    entry_incident_malware_name.delete(0, "end")
    entry_incident_url.delete(0, "end")


# CLEAR FIELDS BUTTON THAT UTILIZES THE CLEAR_FIELDS FUNCTION DEFINED FOR SIEM ALERT
clear_alert_button = ttk.Button(
    siemalert_subtab1, text="Clear", command=clear_malfile_fields)
clear_alert_button.grid(column=1, row=12)

# SIEM ALERT GENERATE OUTPUT BUTTON
button_siem_alert = tk.Button(
    siemalert_subtab1, text="Generate Output", command=siem_malware_alert)
button_siem_alert.grid(column=0, row=12)

# DEFINE FUNCTIONS FOR IPS BLOCK SUBTAB ON SIEMALERT TAB

siemalert_subtab2 = ttk.Frame(sub_notebook)
sub_notebook.add(siemalert_subtab2, text='IPS Block')


def siem_IPS_alert():

    # ENTRY VALUES FOR SIEM ALERT TAB
    incident_IPS_firewall_customer = entry_incident_IPS_firewall_customer.get()
    incident_IPS_location = entry_incident_IPS_location.get()
    incident_IPS_timestamp = entry_incident_IPS_timestamp.get()
    incident_IPS_source_ip = entry_incident_IPS_source_ip.get()
    incident_IPS_destination_ip = entry_incident_IPS_destination_ip.get()
    incident_IPS_attack_category = entry_incident_IPS_attack_category.get()

    # REPLACE PERIODS WITH BRACKETS
    incident_IPS_source_ip = incident_IPS_source_ip.replace('.', '[.]')
    incident_IPS_destination_ip = incident_IPS_destination_ip.replace(
        '.', '[.]')

    # SIEM ALERT TEMPLATE
    alert_output = f"Dear {incident_IPS_firewall_customer},\n"
    alert_output += "\n"
    alert_output += "Our firewall has detected and dropped multiple connection attempts from a remote IP. Details can be seen below.\n"
    alert_output += "\n"
    alert_output += f"Incident Location => {incident_IPS_location}\n"
    alert_output += "\n"
    alert_output += f"Incident Timestamp => {incident_IPS_timestamp}\n"
    alert_output += "\n"
    alert_output += f"Source IP => {incident_IPS_source_ip} \n"
    alert_output += "\n"
    alert_output += f"Destination IP => {incident_IPS_destination_ip}\n"
    alert_output += "\n"
    alert_output += f"Incident Detail => Attack Categorization: {incident_IPS_attack_category}\n"
    alert_output += "\n"
    alert_output += "Company recommends that you consult with your IT Support to ensure all computer hardware/software is up to date with the latest security patches and updates. We also recommend consulting with your IT Support to ensure no further suspicious activity has been detected.\n"
    alert_output += "\n"
    alert_output += "At your request, we can take necessary steps to block this Source IP from communicating with your network.\n"
    alert_output += "\n"
    alert_output += "Thanks,\n\n"
    alert_output += "Company \n"
    alert_output += "Contact: security@domain.com"

    # OUTPUT BOX DISPLAYED AFTER HITTING GENERATE OUTPUT BUTTON ON SIEM ALERT TAB
    siem_alert_output = scrolledtext.ScrolledText(
        siemalert_subtab2, width=80, height=45)
    siem_alert_output.insert("insert", alert_output)
    siem_alert_output.grid(column=2, row=0, rowspan=12)


empty_box = scrolledtext.ScrolledText(
    siemalert_subtab2, width=75, height=45)
empty_box.grid(column=2, row=0, rowspan=12)

# SIEM ALERT WIDGETS
# INPUT IT TEAM NAME INTO SIEM ALERT TAB USING GRID GEOMETRY MANAGER
ttk.Label(siemalert_subtab2, text="Firewall POC or Team: ").grid(
    column=0, row=0)
entry_incident_IPS_firewall_customer = ttk.Entry(siemalert_subtab2)
entry_incident_IPS_firewall_customer.grid(column=1, row=0)

# INPUT APPLICATION NAME INTO SIEM ALERT TAB USING GRID GEOMETRY MANAGER
ttk.Label(siemalert_subtab2, text="Incident Location Name: ").grid(
    column=0, row=1)
entry_incident_IPS_location = ttk.Entry(siemalert_subtab2)
entry_incident_IPS_location.grid(column=1, row=1)

# INPUT RULE BROKEN INTO SIEM ALERT TAB USING GRID GEOMETRY MANAGER
ttk.Label(
    siemalert_subtab2, text="Incident Timestamp(XX:XX on MM/DD/YYYY)").grid(column=0, row=2)
entry_incident_IPS_timestamp = ttk.Entry(siemalert_subtab2)
entry_incident_IPS_timestamp.grid(column=1, row=2)

# INPUT TIME MONTH DATE YEAR INTO SIEM ALERT TAB USING GRID GEOMETRY MANAGER
ttk.Label(siemalert_subtab2, text="Source IP:").grid(column=0, row=3)
entry_incident_IPS_source_ip = ttk.Entry(siemalert_subtab2)
entry_incident_IPS_source_ip.grid(column=1, row=3)

#  INPUT EVENT DESCRIPTION INFORMATION INTO SIEM ALERT TAB USING GEOMETRY GRID MANAGER
ttk.Label(siemalert_subtab2, text="Destination IP:").grid(column=0, row=6)
entry_incident_IPS_destination_ip = tk.Entry(siemalert_subtab2)
entry_incident_IPS_destination_ip.grid(column=1, row=6)

# INPUT ORGANIZATION INFORMATION INTO SIEM ALERT TAB USING GEOMETRY GRID MANAGER
ttk.Label(siemalert_subtab2, text="Fortiguard Attack Categorization:").grid(
    column=0, row=7)
entry_incident_IPS_attack_category = ttk.Entry(siemalert_subtab2)
entry_incident_IPS_attack_category.grid(column=1, row=7)

# DEFINE THE CLEAR FIELDS FUNCTION FOR SIEM ALERT TAB


def clear_IPS_fields():
    entry_incident_IPS_firewall_customer.delete(0, "end")
    entry_incident_IPS_location.delete(0, "end")
    entry_incident_IPS_timestamp.delete(0, "end")
    entry_incident_IPS_source_ip.delete(0, "end")
    entry_incident_IPS_destination_ip.delete(0, "end")
    entry_incident_IPS_attack_category.delete(0, "end")


# CLEAR FIELDS BUTTON THAT UTILIZES THE CLEAR_FIELDS FUNCTION DEFINED FOR SIEM ALERT
clear_IPS_button = ttk.Button(
    siemalert_subtab2, text="Clear", command=clear_IPS_fields)
clear_IPS_button.grid(column=1, row=12)

# SIEM ALERT GENERATE OUTPUT BUTTON
button_siem_alert = tk.Button(
    siemalert_subtab2, text="Generate Output", command=siem_IPS_alert)
button_siem_alert.grid(column=0, row=12)

# DEFINE EMAIL BLOCK SUBTAB IN SIEM ALERT MAINTAB
siemalert_subtab3 = ttk.Frame(sub_notebook)
sub_notebook.add(siemalert_subtab3, text='Email Block')


def siem_email_alert():

    # ENTRY VALUES FOR SIEM ALERT TAB
    incident_email_firewall_customer = entry_incident_email_firewall_customer.get()
    incident_email_location = entry_incident_email_location.get()
    incident_email_timestamp = entry_incident_email_timestamp.get()
    incident_email_source_ip = entry_incident_email_source_ip.get()
    incident_email_hostname = entry_incident_email_hostname.get()
    incident_email_malware_name = entry_incident_email_malware_name.get()
    incident_email_address = entry_incident_email_address.get()
    incident_email_subject_line = entry_incident_subject_line.get()
    incident_email_attachment = entry_incident_attachment.get()

    # REPLACE PERIODS WITH BRACKETS
    incident_email_address = incident_email_address.replace('.', '[.]')

    # SIEM ALERT TEMPLATE
    alert_email_output = f"Dear {incident_email_firewall_customer},\n"
    alert_email_output += "\n"
    alert_email_output += "Our firewall has detected and blocked an attempt to download a malicious file. Details can be seen below.\n"
    alert_email_output += "\n"
    alert_email_output += f"Incident Location => {incident_email_location}\n"
    alert_email_output += "\n"
    alert_email_output += f"Incident Timestamp => {incident_email_timestamp}\n"
    alert_email_output += "\n"
    alert_email_output += f"Incident Source (IP and Hostname) => {incident_email_source_ip} ({incident_email_hostname})\n"
    alert_email_output += "\n"
    alert_email_output += f"Incident Details or Malware Name => {incident_email_malware_name}\n"
    alert_email_output += "\n"
    alert_email_output += f"Suspect Email Address => {incident_email_address}\n"
    alert_email_output += "\n"
    alert_email_output += f"Suspect Email Subject Line => {incident_email_subject_line}\n"
    alert_email_output += "\n"
    alert_email_output += f"Suspect Email Attachment => {incident_email_attachment}\n"
    alert_email_output += "\n"
    alert_email_output += "Company recommends that you consult with your IT Support to ensure all computers are up-to-date with the latest security patches and updates. We also recommend consulting with your IT Support to ensure all software is patched and updated as well. Additionally, we recommend identifying and remediating any further emails from this remote address.\n"
    alert_email_output += "\n"
    alert_email_output += "At your request, we can take the necessary steps to block this computer from your network, if needed.\n"
    alert_email_output += "\n\n"
    alert_email_output += "Thanks,\n\n"
    alert_email_output += "Company \n"
    alert_email_output += "Contact: company@domain.com"

    # OUTPUT BOX DISPLAYED AFTER HITTING GENERATE OUTPUT BUTTON ON SIEM ALERT TAB
    siem_alert_output = scrolledtext.ScrolledText(
        siemalert_subtab3, width=85, height=45)
    siem_alert_output.insert("insert", alert_email_output)
    siem_alert_output.grid(column=2, row=0, rowspan=12)


empty_box = scrolledtext.ScrolledText(
    siemalert_subtab3, width=85, height=45)
empty_box.grid(column=2, row=0, rowspan=12)

# SIEM ALERT WIDGETS
# INPUT IT TEAM NAME INTO SIEM ALERT TAB USING GRID GEOMETRY MANAGER
ttk.Label(siemalert_subtab3, text="Firewall POC or Team: ").grid(
    column=0, row=0)
entry_incident_email_firewall_customer = ttk.Entry(siemalert_subtab3)
entry_incident_email_firewall_customer.grid(column=1, row=0)

# INPUT APPLICATION NAME INTO SIEM ALERT TAB USING GRID GEOMETRY MANAGER
ttk.Label(siemalert_subtab3, text="Incident Location Name: ").grid(
    column=0, row=1)
entry_incident_email_location = ttk.Entry(siemalert_subtab3)
entry_incident_email_location.grid(column=1, row=1)

# INPUT RULE BROKEN INTO SIEM ALERT TAB USING GRID GEOMETRY MANAGER
ttk.Label(
    siemalert_subtab3, text="Incident Timestamp(XX:XX on MM/DD/YYYY)").grid(column=0, row=2)
entry_incident_email_timestamp = ttk.Entry(siemalert_subtab3)
entry_incident_email_timestamp.grid(column=1, row=2)

# INPUT TIME MONTH DATE YEAR INTO SIEM ALERT TAB USING GRID GEOMETRY MANAGER
ttk.Label(siemalert_subtab3, text="Source IP:").grid(column=0, row=3)
entry_incident_email_source_ip = ttk.Entry(siemalert_subtab3)
entry_incident_email_source_ip.grid(column=1, row=3)

#  INPUT EVENT DESCRIPTION INFORMATION INTO SIEM ALERT TAB USING GEOMETRY GRID MANAGER
ttk.Label(siemalert_subtab3, text="Target Hostname:").grid(column=0, row=6)
entry_incident_email_hostname = tk.Entry(siemalert_subtab3)
entry_incident_email_hostname.grid(column=1, row=6)

# INPUT ORGANIZATION INFORMATION INTO SIEM ALERT TAB USING GEOMETRY GRID MANAGER
ttk.Label(siemalert_subtab3, text="Fortiguard Malware Name:").grid(
    column=0, row=7)
entry_incident_email_malware_name = ttk.Entry(siemalert_subtab3)
entry_incident_email_malware_name.grid(column=1, row=7)

# INPUT HOST NAME INFORMATION INTO SIEM ALERT TAB USING GEOMETRY GRID MANAGER
ttk.Label(siemalert_subtab3, text="Suspect Email Address: ").grid(
    column=0, row=8)
entry_incident_email_address = ttk.Entry(siemalert_subtab3)
entry_incident_email_address.grid(column=1, row=8)

ttk.Label(siemalert_subtab3, text="Suspect Subject Line: ").grid(
    column=0, row=9)
entry_incident_subject_line = ttk.Entry(siemalert_subtab3)
entry_incident_subject_line.grid(column=1, row=9)

ttk.Label(siemalert_subtab3, text="Suspect Email Attachment: ").grid(
    column=0, row=10)
entry_incident_attachment = ttk.Entry(siemalert_subtab3)
entry_incident_attachment.grid(column=1, row=10)

# DEFINE THE CLEAR FIELDS FUNCTION FOR SIEM ALERT TAB


def clear_email_fields():
    entry_incident_email_firewall_customer.delete(0, "end")
    entry_incident_email_location.delete(0, "end")
    entry_incident_email_timestamp.delete(0, "end")
    entry_incident_email_source_ip.delete(0, "end")
    entry_incident_email_hostname.delete(0, "end")
    entry_incident_email_malware_name.delete(0, "end")
    entry_incident_email_address.delete(0, "end")
    entry_incident_subject_line.delete(0, "end")
    entry_incident_attachment.delete(0, "end")


# CLEAR FIELDS BUTTON THAT UTILIZES THE CLEAR_FIELDS FUNCTION DEFINED FOR SIEM ALERT
clear_email_button = ttk.Button(
    siemalert_subtab3, text="Clear", command=clear_email_fields)
clear_email_button.grid(column=1, row=12)

# SIEM ALERT GENERATE OUTPUT BUTTON
button_siem_alert = tk.Button(
    siemalert_subtab3, text="Generate Output", command=siem_email_alert)
button_siem_alert.grid(column=0, row=12)

root.mainloop()
