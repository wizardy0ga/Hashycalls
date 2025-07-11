# Using hashycalls from the CLI

![help](../../../img/cli-help.png)

> ![IMPORTANT]To use hashycalls from the command line, the module must be installed & the scripts directory must be available in your path.

## The minimum

At a minimum, the user must specify the apicalls to hash. This is done with **-a, --apicalls** or **-f, --file**. If using a file, each api call should be seperated by a new line. Hashycalls will use it's default settings from there.

###### From the command ine
```ps
hashycalls --apicalls VirtualAllocEx, WriteProcessMemory, CreateRemoteThread, OpenProcess
```

###### With a file

```ps
hashycalls --file .\calls.txt
```

```
/* calls.txt */
VirtualAllocEx
WriteProcessMemory
CreateRemoteThread
OpenProcess
```

## Build Options
These options control how the final template looks & functions. These options don't need to be specified but can be used to tailor the template to your needs. 

### seed ( int )
This defines the value of the seed for the hashing algorithm. Specifically, this defines the value of the **HASH_SEED** macro in hashycalls.c which is used as the initial seed for the hashing function in the template.

### algo
The algo option sets the hashing algorithm for the function calls. 

### outdir
This argument instructs hashycalls to dump the template to a specific directory. If no outdir is specified, hashycalls writes the template to the current working directory of the shell. 

### debug
This does nothing more than enable debug statements in the hashycalls source code. This is for monitoring & troubleshooting purposes.

### globals
This option enables global access to the hashed api. Without this option, the structure must be passed around the program. In theory, this should support position independence however this hasn't been tested with this code base.

### remove_comments
This option will remove the comments from all source code.

### api_list_name
This sets a name for the variable which holds the hashed api structure within the code base. Some of the template code requires this variable to be the same so this option provides the developer the option for naming the variable.