[![Typing SVG](https://readme-typing-svg.herokuapp.com?font=Press+Start+2P&size=72&duration=500&pause=3000&color=F7071D&center=true&width=1250&height=180&lines=Hashycalls)](https://git.io/typing-svg)
[![Typing SVG](https://readme-typing-svg.herokuapp.com?font=Press+Start+2P&size=15&duration=5&pause=3000&color=F7071D&center=true&width=1250&lines=An+Import+Address+Table+obfuscation+utility+for+C%2FC%2B%2B+based+windows+implants)](https://git.io/typing-svg)
# About
Hashycalls is an import address table obfuscation utility for C/C++ implants targeting the windows operating system. This tool automates the process of creating hashes & associated resolution code. Developers need only provide a list of api calls to generate the hashycalls template. Implant side, this template  can be used to access all of the function calls. Upon compilation, the function calls **will not appear** in the import address table.   

# Limitations
The hashycalls module itself is only intended for use on windows. Linux is not currently supported however this feature is not off the table.

The template only supports x64 based implants. 
# Installation

###### Manual Installation
```
git clone https://github.com/wizardy0ga/hashycalls
pip install .\hashycalls
```

###### Via PyPi
```
pip install hashycalls
```

# Documentation
## Module
[Using hashycalls from the command line](https://github.com/wizardy0ga/Hashycalls/blob/master/docs/en/usage/hashycalls/command%20line.md)  
[Using hashycalls in a script](https://github.com/wizardy0ga/Hashycalls/blob/master/docs/en/usage/hashycalls/scripting.md)
## Template 
[Using the hashycalls template file](https://github.com/wizardy0ga/Hashycalls/blob/master/docs/en/usage/template/hashycalls.md)

## Tutorials
[Writing a basic injector with hashycalls](https://github.com/wizardy0ga/Hashycalls/blob/master/docs/en/tutorials/writing-a-basic-injector.md)  
[Writing a compilation script for the basic injector](https://github.com/wizardy0ga/Hashycalls/blob/master/docs/en/tutorials/writing-a-compilation-script-for-basic-injector.md)

# Basic Usage
This provides a brief synopsis on using the module & generated template file.

## Hashcalls Module
The module is the first step to using this in your project. The module provides user interfaces from the command line & in python scripts for automating your implants build routine.

### From the Command Line
If your python **Scripts** directory is in your PATH variable, the **hashycalls** command can be accessed from the command line. This provides ease of access for generating templates & writing them to applicable directories. Click [here](docs/en/usage/hashycalls/commandline.md) for further command line usage information.

![help](docs/img/cli-help.png)

### In a Script
Hashycalls provides the **HashyCalls** class which is a container for the associated source & header files. This interface allows developers to import & modify the source code within their own automated build routines. Click [here](docs/en/usage/hashycalls/scripting.md) for more information on this topic.

```py
from hashycalls import HashyCalls
hashysource = HashyCalls(
    apicalls        = [ 'OpenProcess', 'VirtualAllocEx', 'WriteProcessMemory', 'CreateRemoteThread' ]
    , algo          = 'djb2'
    , globals       = True
    , api_list_name = 'pHashyCalls'
    , seed          = 782
    , debug         = False 
)
hashysource.source.write_to_dir('src')
hashysource.header.write_to_dir('inc')
```

## Hashycalls Template
To use hashycalls in your implant, include the **hashycalls.h** header file in any source file where you need to access the hidden function calls. **InitApiCalls** needs to be called once during runtime to populate the hashed api structure. From there, developers can access function calls using the structure itself or the **EXEC** macro.

```c
# include "hashycalls.h"
int main()
{

/* Initialize the hashed api calls */
# ifdef hc_GLOBAL
	if ( !InitApiCalls() )
		return -1;
# endif

# ifndef  hc_GLOBAL
	PHWINAPI hWin32;
	if ( ( hWin32 = InitApiCalls() ) == NULL )
		return -1;
# endif

    /* Running some functions using both sytax styles */
	hWin32->Kernel32.GetCurrentProcessId();
	EXEC( User32, MessageBoxA ) ( 0, "Testing", "Hashed MessageBoxA", MB_OK );

	return 0;
}
```

# Credits
Have to give credit where it's do!

## [Cracked5pider](https://github.com/Cracked5pider)
The **HWINAPI** structure is heavily influenced by Cracked5piders [INSTANCE](https://github.com/HavocFramework/Havoc/blob/41a5d45c2b843d19be581a94350c532c1cd7fd49/payloads/DllLdr/Include/Core.h#L36) structure for grouping api calls in the havoc payload. Check out the [havoc framwork](https://github.com/HavocFramework/Havoc) repository & [website](https://havocframework.com).

## [reverseame](https://github.com/reverseame)
reverseame has provided a repository containing a dataset for the entire windows API in JSON. This dataset has proven to be very useful for some of my projects, having saved me the time & effort of creating one myself. Checkout the [winapi-categories](https://github.com/reverseame/winapi-categories) repository for yourself.

## [vx-underground](https://github.com/vxunderground)
[VX-API](https://github.com/vxunderground/VX-API) is a great repo!