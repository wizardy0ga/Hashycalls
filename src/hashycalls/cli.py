import os
import uuid
from hashycalls.colors import *
from hashycalls.core import *
from hashycalls.args import parse_user_args

# ----------------- Private Functions ------------------
def print_banner( key_width: int, val_width: int ) -> int:
    """ Print the hashycalls banner """
    # Determine amount of minimum space required for the banner. This is the longest string.
    ret = 0
    description = "An Import Address Table obfuscation utility for C/C++ windows implants"
    if ( key_width + val_width ) < len( description ):
        val_width = ( ( len( description ) - key_width ) + 2 )
        ret = val_width

    # print it
    print( f"{ RED }╔{ '═' * ( key_width + val_width + 4) }╗" )
    print( f"║{ WHITE }{ '_  _ ____ ____ _  _ _   _    ____ ____ _    _    ____'.center( val_width + key_width + 4, ' ' ) }{ RED }║")
    print( f"║{ WHITE }{'|__| |__| [__  |__|  \\_/  __ |    |__| |    |    [__'.center( val_width + key_width + 2, ' ' ) }  { RED }║")
    print( f"║{ WHITE }{'|  | |  | ___] |  |   |      |___ |  | |___ |___ ___]'.center( val_width + key_width + 4, ' ' ) }{ RED }║")
    print( f"║{' '.center( key_width + val_width + 4, ' ' ) }{ RED }║")
    print( f"║{ RED }{ description.center( val_width + key_width + 4, ' ' ) }{ RED }║")
    print( f"║{ 'Coded By: Wizardy0ga'.center( val_width + key_width + 4 ) }║")
    print( f"║{ f'Version: { VERSION }'.center( key_width + val_width + 4 ) }║")
    print( f"║{' '.center( key_width + val_width + 4, ' ' ) }{ RED }║")

    return ret

def _format_args( action, default_metavar: str ) -> str:
    """ 
    Format an arguments syntax. Taken from argparse.HelpFormatter class. This is a combination of the 
    the _format_args & _metavar_formatter() methods fo the HelpFormatter class.
    """
    # Set the metavar for the argument
    if action.metavar is not None:
        metavar = action.metavar
    elif action.choices is not None:
        metavar = '{%s}' % ','.join( map( str, action.choices ) )
    else:
        metavar = default_metavar
    
    # Format argument string based on number of arguments
    match action.nargs:
        case None:
            result = '%s' % metavar
        case '?':               # OPTIONAL:
            result = '[%s]' % metavar
        case '*':               # ZERO_OR_MORE:
            metavar = metavar
            if len(metavar) == 2:
                result = '[%s [%s ...]]' % metavar
            else:
                result = '[%s ...]' % metavar
        case '+':               # ONE_OR_MORE:
            result = '%s [%s ...]' % (metavar, metavar)
        case '...':             # REMAINDER:
            result = '...'
        case 'A...':            # PARSER:
            result = '%s ...' % metavar
        case '==SUPPRESS==':    # SUPPRESS:
            result = ''
        case _:
            result = ''
    return result


def print_help( parser ) -> str:
    """ Prints a table using the arguments stored in an argparse.ArgumentParser object as a table"""
    max_key_width   = 0
    max_val_width   = 0
    args            = {}
    # Collect argument group, variable name & help inforamation. Get the max lengths
    # of each argument & description string for formatting the table.
    # Examples -> Arg = -k, --key KEY | Desc = 'Your API key'
    # Structure -> { 'Argument Group': [{'Arg': '-k, --key KEY', 'Desc': 'Your API key'}] }
    for argument_group in parser._action_groups:
        if argument_group._group_actions:
            if argument_group.title == 'options':
                setattr( argument_group, 'title', 'Module Options' )
            args[ argument_group.title ] = []
            for argument, index in zip( argument_group._group_actions, range( 0, len( argument_group._group_actions ) ) ):
                args[ argument_group.title ] += [ { 'arg': f'{ ', '.join( argument.option_strings ) } { _format_args(argument, argument.dest.upper()) }', 'desc': argument.help } ]
                key_width = len( args[ argument_group.title ][ index ][ 'arg' ] ) + 4
                val_width = len( args[ argument_group.title ][ index ][ 'desc' ] ) + 4
                max_key_width = key_width if key_width > max_key_width else max_key_width
                max_val_width = val_width if val_width > max_val_width else max_val_width

    # Begin building the table string
    max_width = max_key_width + max_val_width
    table = f"╠{ '═' * max_width }╣\n"
    for argument_group, arguments in args.items():
        table += f'║{ GREEN }{ argument_group.center(max_width, ' ') }{ RED }║\n'
        table += f'╠{ '═' * max_key_width }╦{ '═' * ( max_val_width - 1 ) }╣\n'
        for argument in arguments:
            table += f'║ { WHITE }{ argument['arg'].ljust( max_key_width - 1 ) }{ RED }║ { YELLOW }{ argument['desc'].ljust( max_val_width - 2 ) }{ RED }║\n'
            if argument_group == list( args.keys() )[-1] and argument == arguments[-1]:
                table += f'╚{ '═' * max_key_width }╩{ '═' * ( max_val_width - 1 ) }╝'
            elif argument == arguments[-1]:
                table += f'╠{ '═' * max_key_width }╩{ '═' * ( max_val_width - 1 ) }╣\n'
            else:
                table += f'╠{ '═' * max_key_width }╬{ '═' * ( max_val_width - 1 ) }╣\n'
    
    print_banner( max_key_width -2, max_val_width - 2 )
    print( table + END )


def print_config( dictionary: dict ) -> None:
    """ Prints argument configuration & banner """
    key_width  = max( len( str( key ) ) for key in dictionary ) + 1
    val_width  = max( len( str( val ) ) for val in dictionary.values() ) + 2

    required_size = print_banner( key_width, val_width )
    val_width = required_size if val_width < required_size else val_width


    # Create sections of the config
    top         = f"{ RED }╠{ '═' * ( key_width + 1 ) }╦{ '═' * ( val_width + 2 ) }╣"
    header      = f"║ { PURPLE }{ 'Option'.ljust( key_width ) }{ RED }║ { PURPLE }{ 'Value'.ljust( val_width ) }{ RED } ║"
    separator   = f"╠{ '═' * ( key_width + 1 ) }╬{ '═' * ( val_width + 2 ) }╣"
    bottom      = f"╚{ '═' * ( key_width + 1 ) }╩{ '═' * ( val_width + 2)  }╝"

    # Print top half of config
    for obj in [ top, header, separator ]:
        print( obj )

    # Print items in config
    for key, val in dictionary.items():
        print(f"║ { WHITE }{ str( key ).ljust( key_width ) }{ RED }║ { YELLOW }{ str( val ).ljust( val_width ) }{ RED } ║")

    # Print the bottom of the config
    print(bottom)


def hc_print( msg: str ) -> None:
    """ Override for print function """
    print(f"{ RED }[ { WHITE }> { RED }] { YELLOW } { msg } { END }")


# ----------------- Export Functions -------------------
def main():
    parser  = parse_user_args()
    args    = parser.parse_args()

    if args.help:
        print_help( parser )
        exit()

    if args.version:
        hc_print( f' Module:   { SCRIPT_VERSION }\n\tTemplate: { TEMPLATE_VERSION }' )
        exit()

    output_directory = os.path.join( os.getcwd(), args.outdir )

    # Get api calls from user
    user_api_call_imports = None
    if not args.file and not args.apicalls:
        hc_print('No api calls were given to the script. Specify a list of functions with --file or --apicalls. Use -h for further information')
        exit()
    if args.apicalls:
        user_api_call_imports = args.apicalls
    else:
        with open( args.file, 'r' ) as file:
            user_api_call_imports = file.read().split( '\n' ) 
    try:
        # Create header & source files
        hashycalls = HashyCalls( 
            apicalls        = user_api_call_imports
            , globals       = args.globals
            , api_list_name = args.api_list_name
            , algo          = args.algo
            , seed          = args.seed
            , debug         = args.debug     
        )
    except Exception as e:
        hc_print( f'{ RED }hashycalls initialization failed with error: { END }{ e }' )
        exit()

    try:

        # Print config
        if not args.quiet:
            args_dict = vars( args )
            for arg in [ 'apicalls', 'file', 'help', 'version', 'quiet' ]:
                del args_dict[ arg ]
            print_config( args_dict )

        hc_print( f"Imported { len( hashycalls.header.api_call_list.apicalls ) } functions:" )
        for function in hashycalls.header.api_call_list.apicalls:
            print( f"\t{ GREEN }+ { WHITE }{ function.name } { END }" )

        # Remove comments
        if args.remove_comments:
            [ file.remove_comments() for file in [ hashycalls.header, hashycalls.source ] ]
            hc_print( "Removed comments from source code" )

        # Cleanup new lines
        for file in [ hashycalls.header, hashycalls.source ]:
            file.remove_blank_lines()

        # Insert header to file
        build_id = str( uuid.uuid4() )
        hc_print( f"Assigned id { WHITE }{ build_id }{ YELLOW } to this build" )
        for file in [ hashycalls.header, hashycalls.source ]:
            file.insert_header( additional_content = f'ID: { build_id }\nUsing function calls:\n\t[+] - { '\n\t[+] - '.join( user_api_call_imports ) }' )

        # Write files to disk
        hashycalls.header.write_to_dir( output_directory )
        hashycalls.source.write_to_dir( output_directory )

        for file in [ hashycalls.header, hashycalls.source ]:
            hc_print( f"Wrote { WHITE }{ file.filename }{ YELLOW } to { WHITE }{ file.path_on_disk }" )
    
    except Exception as e:
        hc_print(f"An unexpected error occurred. -> { e }")