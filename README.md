<h1 style="font-size: 36px;">SOCTools</h1>

<img width="1417" alt="Screen Shot 2023-05-10 at 8 05 22 PM" src="https://github.com/MarstotheBars/SOCTools/assets/49597642/d9fe6fae-4aee-4127-8750-0b368ae96324">

SOCTools is a Python tool that utilizes the TKinter GUI platform for easy navigation and execution. It is built with minimal outside modules, relying solely on default Python packages to streamline the installation process.

This project is based off the FortiEDR Platform, which performs API Calls to Fortinets EDR as well as creates queries based off a .txt file located in the same directory (Designated by you)

<h2 style="font-size: 24px;">How to use</h2>
To effectively use the tool, all you will need to do is edit the Templates that are in use as shown below. 

<img width="986" alt="Screen Shot 2023-05-10 at 9 13 10 PM" src="https://github.com/MarstotheBars/SOCTools/assets/49597642/f4c23976-3003-479d-9d3e-a9e9594558fd">

Each line represents a line of text and the /n character represents when a new line is inserted. If you want to add more variables simply add more by adding lines to the following and FOLLOW THE SYNTAX. See below

<img width="537" alt="Screen Shot 2023-05-10 at 9 14 07 PM" src="https://github.com/MarstotheBars/SOCTools/assets/49597642/d2be4ec7-0ca6-41f4-b700-199722083d07">

To add a physical button follow the snytax below
<img width="667" alt="Screen Shot 2023-05-10 at 9 14 18 PM" src="https://github.com/MarstotheBars/SOCTools/assets/49597642/08b502f9-e9fc-4374-a10f-4fb2d5163718">

Make sure you edit the 'Clear fields' option as well. Otherwise you won't be able to easily create and delete entries. Command + C is only option available. 

<img width="385" alt="Screen Shot 2023-05-10 at 9 17 26 PM" src="https://github.com/MarstotheBars/SOCTools/assets/49597642/042a44e3-0be4-4999-8d35-cccd9c231769">


<h2 style="font-size: 24px;">Getting Started</h2>

To run SOCTools, you will need to have Python 3.9 installed on your machine. Once installed, you can simply load Python 3.9 and install the necessary modules by running the following command:

pip3 install tkinter webbrowser subprocess re

<h2 style="font-size: 24px;">Usage</h2>


To use SOCTools, simply navigate to the directory where the tool is installed and run the following command:

python3 case.py

This will open the tool's graphical user interface (GUI), which will allow you to easily navigate and execute the desired functions.

<h2 style="font-size: 24px;">Configuring the Config.ini file</h2>

The config.ini file contains sensitive information that is used by Project Name to function properly. Therefore, it is important to secure the file by properly configuring it. Here are some steps to help you achieve this:

 1. Set the file permissions to 600 (read and write for owner only).
 2. Move the file outside of the project directory, preferably to a location that is not publicly accessible.
 3. If you need to make changes to the file, copy it to a safe location, make the changes, and then copy it back to its secure location.

By following these steps, you can help ensure that the sensitive information in the config.ini file remains secure.

<h1 style="font-size: 24px;">Acknowledgements </h1>
Special thanks to the developers of the TKinter, webbrowser, subprocess, and re Python packages, without which this tool would not be possible.
