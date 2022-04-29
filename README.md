# Advanced Kodi Launcher : Nvidia Gamestream plugin

Nvidia Gamestream plugin for AKL which enables you to scan the games available in your Gamestream library and launch them from AKL.

| Release | Status |
|----|----|
| Stable |[![Build Status](https://dev.azure.com/jnpro/AKL/_apis/build/status/script.akl.nvgamestream?branchName=main)](https://dev.azure.com/jnpro/AKL/_build/latest?definitionId=13&branchName=main) |
| Unstable | [![Build Status](https://dev.azure.com/jnpro/AKL/_apis/build/status/script.akl.nvgamestream?branchName=dev)](https://dev.azure.com/jnpro/AKL/_build/latest?definitionId=13&branchName=dev) |

### Kodi forum thread ###

More information and discussion about AKL can be found in the [Advanced Kodi Launcher thread] 
in the Kodi forum.

[Advanced Kodi Launcher thread]: https://forum.kodi.tv/showthread.php?tid=366351

### Documentation ###

Read more about AKL on the main plugin's [ReadMe](https://github.com/chrisism/plugin.program.akl/blob/master/README.md) page.

# Pairing with Nvidia Gamestream PC #

We now have the ability to launch PC games through Nvidia gamestreaming. To scan for the available games on your
PC we need to pair with the PC running Geforce Experience and for this we need valid certificates to have a secure and encrypted connection with your Gamestream PC. However, creating the needed certificates might not always be properly supported in your Kodi installation. So in the case it is not supported to create the valid certificates and finish up the pairing process you need to do one of the following actions.

## 1. Use OpenSSL to create the certificate
You will need to install the correct [OpenSSL](https://github.com/openssl/openssl) version for your OS.
After that you can create the certificate using the tool.

## 2. Run custom pairing python scripts 

Download the source code for AKL from github and place it on your computer. Make sure you have Python installed and go to the root of the code directory with a command line or bash.  
1. First we create a new virtual environment for python using the command ```python -m venv .venv```
2. Then activate the venv with:
   - On Unix or MacOS, using the bash shell: ```source /path/to/venv/bin/activate```
   - On Unix or MacOS, using the csh shell: ```source /path/to/venv/bin/activate.csh```
   - On Unix or MacOS, using the fish shell: ```source /path/to/venv/bin/activate.fish```
   - On Windows using the Command Prompt: ```path\to\venv\Scripts\activate.bat```
   - On Windows using PowerShell: ```path\to\venv\Scripts\Activate.ps1```
3. Install needed packages with the command ```pip install -r requirements.txt```

Now you are ready to execute the needed commands. With the virtual environment still activated, you can 
execute the tools.  
To create a new certificate execute the following command with the location for the certificates as an argument.

Example: 
```
>python ./resources/tools/create_certificates.py c:\games\gamestream\
```

To pair with the gamestream server use the following command. Arguments are the Gamestreamserver host IP and the path
to the certificates.

Example: 
```
>python ./resources/tools/pair_with_gspc.py 192.168.1.99 c:\games\gamestream\
```

When started, this tool will show a unique pincode which you need to enter in a dialog on your computer which is running 
Nvidia Geforce Experience. When done correctly it will pair up with that computer and generate certificates needed to 
keep on communicating with the geforce experience computer. These certificates can be used in a Gamestream Launcher when
running AKL in Kodi.

## 3. Use certificates from Moonlight

If you have installed Moonlight as your client for Nvidia Gamestream and you already used that to pair with your Gamestream
server, then you can reuse those certificates. Out of the box the certificates are not yet ready to be used with the AKL scripts.
You will need to have OpenSSL on your computer to transform the private key certificate to the supported format.

Execute the following command with OpenSSL:
```
openssl pkcs8 -topk8 -inform DER -outform PEM -nocrypt -in <MOONLIGHT_KEY_FILE_PATH>.key -out <YOUR_FILE_NAME>.key
```

Copy the new *.key and *.crt to a separate folder. Now you can use these certificate files when creating your launcher in AKL in Kodi.