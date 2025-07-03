import os
import random
import argparse

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


def parse_user_args() -> argparse.Namespace:
    """ Parses command line arguments and returns as namespace object for further processing the caller """
    parser = argparse.ArgumentParser()
    parser.add_argument( 
        '-o'
        , '--outdir'
        , default   = os.getcwd()
        , type      = dir_exists
        , help      = 'A directory to write the source files to. Defaults to "Out" directory.'
    )

    parser.add_argument(
        '--version'
        , default   = False
        , action    = 'store_true'
        , help      = 'show the template & script versions then quit.'
    )

    # ------------------- Build Options --------------------
    build_opt_group = parser.add_argument_group( title = "Build Options", description = "Set options to control how hashycalls functions." )
    build_opt_group.add_argument( 
        '-s'
        , '--seed'
        , type      = int
        , default   = random.randrange( 1, 10000 )
        , help      = 'Seed for the hashing algorithm. Generates a random seed if none is provided.' 
    )

    build_opt_group.add_argument(
        '-a'
        , '--algo'
        , choices   = [ 'sdbm', 'djb2' ]
        , default   = 'sdbm'
        , help      = 'An algorithm to hash the api calls with. Defaults to sdbm.'
    )
    
    build_opt_group.add_argument(
        '--debug'
        , action    = 'store_true'
        , default   = False
        , help      = 'Enables debug statements' 
    )

    build_opt_group.add_argument(
        '--globals'
        , action    = 'store_true'
        , default   = False
        , help      = 'Enables a globally accessible api structure.'
    )

    build_opt_group.add_argument(
        '--remove_comments'
        , action    = 'store_true'
        , default   = False
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
        '--apicalls'
        , type      = str
        , nargs     = "+"
        , help      = 'List of win32 api calls to generate a template for'
    )
    
    input_arg_group.add_argument(
        '--file'
        , type    = file_exists
        , default = False
        , help    = 'Path to file containing a list of api calls. Use a new line [\\n] to seperate each api call.' 
    )

    return parser.parse_args()