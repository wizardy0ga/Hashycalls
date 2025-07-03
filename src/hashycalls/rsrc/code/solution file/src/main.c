# define _CRT_SECURE_NO_WARNINGS

# include <stdio.h>
# include "../src/hashycalls.h"


int main()
{

	DWORD	CurrentPid;
	CHAR	Buffer[ MAX_PATH ]	= { 0 };
	CHAR	Pid[ 10 ]			= { 0 };

# ifdef hc_GLOBAL
	if ( !InitApiCalls() )
		return -1;
# endif

# ifndef  hc_GLOBAL
	PHWINAPI hWin32;
	if ( ( hWin32 = InitApiCalls() ) == NULL )
		return -1;
#endif

	CurrentPid = EXEC( Kernel32, GetCurrentProcessId ) ();
	
	_itoa( CurrentPid, Pid, 10 );
	strcpy( Buffer, "The current pid is: " );
	strcat( Buffer, Pid );

	EXEC( User32, MessageBoxA ) ( 0, Buffer, "Hashed MessageBoxA", MB_OK );

	return 0;
}