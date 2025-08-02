import os
import random
import argparse


# -------------------------- Private Functions --------------------------
def dir_exists( path: str ) -> str:
    """ Validate directory existence for arguments """
    if not os.path.isdir( path ):
        raise argparse.ArgumentTypeError( f"The directory '{ path }' does not exist." )
    return path


def file_exists( path:str ) -> str:
    """ Validate file existence for arguments """
    if not os.path.isfile( path ):
        raise argparse.ArgumentTypeError( f"The file '{ path }' does not exist." )
    return path


# --------------------------- Export Functions ---------------------------
def parse_user_args() -> argparse.ArgumentParser:
    """ Parses command line arguments and returns parser object to caller """
    # ----------------- Module Options -----------------
    parser = argparse.ArgumentParser( add_help = False )    
    parser.add_argument(
        '-h'
        , '--help'
        , default   = False
        , action    = 'store_true'
        , help      = 'Show this message and quit.'
    )
    
    parser.add_argument(
        '-v'
        , '--version'
        , default   = False
        , action    = 'store_true'
        , help      = 'Show the template & script versions then quit.'
    )

    parser.add_argument(
        '-q'
        , '--quiet'
        , default   = False
        , action    = 'store_true'
        , help      = 'Suppress the banner & configuration output'
    )

    # ----------------- Build Options ------------------
    build_opt_group = parser.add_argument_group( title = "Build Options", description = "Set options to control how hashycalls functions." )
    build_opt_group.add_argument( 
        '-s'
        , '--seed'
        , type      = int
        , default   = random.randrange( 1, 10000 )
        , help      = 'Seed for the hashing algorithm. Generates a random seed if none is provided.' 
    )

    build_opt_group.add_argument(
        '-al'
        , '--algo'
        , choices   = [ 'sdbm', 'djb2', 'murmur' ]
        , type      = str
        , default   = 'sdbm'
        , help      = 'An algorithm to hash the api calls with. Defaults to sdbm.'
    )
    
    build_opt_group.add_argument( 
        '-o'
        , '--outdir'
        , default   = os.getcwd()
        , type      = dir_exists
        , help      = 'A directory to write the source files to. Defaults to "Out" directory.'
    )
    
    build_opt_group.add_argument(
        '-d'
        , '--debug'
        , action    = 'store_true'
        , default   = False
        , help      = 'Enables debug statements in the output sourcecode.' 
    )

    build_opt_group.add_argument(
        '-g'
        , '--globals'
        , action    = 'store_true'
        , default   = False
        , help      = 'Enables a globally accessible api structure.'
    )

    build_opt_group.add_argument(
        '-r'
        , '--remove_comments'
        , action    = 'store_true'
        , help      = 'Remove comments from the source code.'
    )
    
    build_opt_group.add_argument(
        '--api_list_name'
        , type      = str
        , default   = 'hWin32'
        , help      = 'Set the name of the api structure variable. This is used when accessing the hashed functions in your code.'
    )

    # ---------------- API Call Inputs -----------------
    input_arg_group = parser.add_mutually_exclusive_group()
    input_arg_group.add_argument(
        '-a'
        , '--apicalls'
        , type      = str
        , nargs     = "+"
        , help      = 'A list of win32 api calls to generate a template for.'
    )
    
    input_arg_group.add_argument(
        '-f'
        , '--file'
        , type      = file_exists
        , help      = 'Path to file containing a list of api calls. Use a new line [\\n] to seperate each api call.' 
    )

    return parser