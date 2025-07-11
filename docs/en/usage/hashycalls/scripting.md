# Using hashycalls in a script

Scripts can be used to automate the compilation of programs. Hashycalls provides an interface for using & manipulating the source code within your own python script.

## The HashyCalls object

```python
class HashyCalls( object ):
    """ Container object for hashycalls header & source files """
    def __init__( self, apicalls: list, globals: bool, api_list_name: str, algo: str, seed: int, debug: bool ):
        self.header = HashycallsHeader( apicalls, globals, api_list_name, algo, seed )
        self.source = HashycallsSource( apicalls, globals, algo, seed, debug )
```

Hashycalls exposes a single object, the **HashyCalls** object. This object contains two properties, **header** and **source**. These represent the hashycalls.h & hashycalls.c files. 

To initialize the object, all of the arguments specified in __init__ must be specified.

| Property | description |
| - | - |
| apicalls | A list of function calls to hash & resolve with the template
| globals | Enables or disables global usage of the api call list
| api_list_name | The name of the variable holding the api call list
| algo | Sets the hashing algorithm for the template
| seed | Sets the seed for the hashing algorithm
| debug | Enables debug statements in template


Both the header & source files are child classes of the same parent. This means they share common properties and methods. Some of these methods are intended for developer use to extend hashycalls functionality into scripting.

### Properties

#### content
Contains the source code associated with the file object.
```py
print( hashycalls.header.content )
print( hashycalls.source.content )
```

#### filename
This property is a filename to use when writing the content to the out directory. Defaults to **hashycalls.c** and **hashycalls.h** respectively.
```py
print( hashycalls.header.filename )
print( hashycalls.source.filename )
```

### Methods

#### replace_content
Uses regex matching to locate & replace code content.
```py
def replace_content( self, new_content: str, pattern: str, count = 1 ) -> None:
    """ Replace the content of a file via regex matching """
```
| argument | description |
| - | - |
| new_content | This will be the new content in the file |
| pattern | A regex pattern for the content to replace |
| count | The amount of times to match & replace the content. Defaults to 1st match. Use 0 to replace all matches |

#### write_to_dir
Writes the code files content to the specified directory.
```py
def write_to_dir( self, directory: str ) -> None:
    """ Write the source file to a directory """
```
| argument | description |
| - | - |
| directory | The path of the directory to write the source code

#### remove_comments
Strips all comments from the source code except for the banner comment at the top of each file.
```py
def remove_comments( self ) -> None:
    """ Remove comments from the source code. """
```

#### remove_blank_lines
Removes all empty lines from the file where consecutive empty lines are >= 2
```py
def remove_blank_lines( self ) -> str:
    """ Remove all blank lines greater than 2 from source """
```

## Script Example
This script will create a hashycalls template with **MessageBoxA** and **GetCurrentProcessId**, drop the main file into the test\src directory & compile the code into an executable. This script demonstrates the ability to automate the creation & compilation of a program with hashycalls

```py
import subprocess
from hashycalls import HashyCalls

# Set file paths
src = "C:\\Users\\Admin\\Test\\Src"
inc = "C:\\Users\\Admin\\Test\\Inc"
main = "C:\\Users\\Admin\\Test\\Src\\main.c"

# Create batch file to compile source code
compiler_code = f"""@echo off
call "C:\\Program Files\\Microsoft Visual Studio\\2022\\Community\\VC\\Auxiliary\\Build\\vcvars64.bat"
cd C:\\Users\\Admin\\Test
cl src\\main.c src\\hashycalls.c
link.exe main.obj hashycalls.obj /OUT:HashycallsTest.exe
"""

# Write main file source code
main_code = """# define _CRT_SECURE_NO_WARNINGS
# include "../Inc/hashycalls.h"
int main()
{

	DWORD	CurrentPid;
	CHAR	Buffer[ MAX_PATH ]	= { 0 };
	CHAR	Pid[ 10 ]			= { 0 };

	if ( !InitApiCalls() )
		return -1;

	CurrentPid = EXEC( Kernel32, GetCurrentProcessId ) ();
	
	_itoa( CurrentPid, Pid, 10 );
	strcpy( Buffer, "The current pid is: " );
	strcat( Buffer, Pid );

	EXEC( User32, MessageBoxA ) ( 0, Buffer, "Hashed MessageBoxA", MB_OK );

	return 0;
}
"""

# Create hashycalls template targeting MessageBoxA & GetCurrentProcessId
hashysource = HashyCalls(
    apicalls        = [ 'MessageBoxA', 'GetCurrentProcessId' ]
    , algo          = 'djb2'
    , globals       = True
    , api_list_name = 'pHashyCalls'
    , seed          = 782
    , debug         = False 
)

# Correct the include statement on the hashycalls.c file
hashysource.source.replace_content( new_content = '# include "../Inc/hashycalls.h"', pattern = '# include "hashycalls.h"')

# Write the source & header to respective directories
hashysource.source.write_to_dir(src)
hashysource.header.write_to_dir(inc)

# Write the main.c code & compiler script
with open( main, 'w' ) as file:
    file.write( main_code )
with open('compiler.bat', 'w') as file:
    file.write( compiler_code )

# Run the compiler script
subprocess.run(['cmd.exe', '/c', 'compiler.bat'])
```