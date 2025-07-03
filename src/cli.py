import os
import uuid
from hashycalls.core import *
from hashycalls.args import parse_user_args

# ----------------- Private Functions ------------------
def print_dict_table( dictionary: dict ) -> None:
    """ Internal function to print banner and configuration"""

    # Determine amount of minimum space required 
    banner_top = "_  _ ____ ____ _  _ _   _    ____ ____ _    _    ____"
    key_width  = max( len( str( key ) ) for key in dictionary ) + 1
    val_width  = max( len( str( val ) ) for val in dictionary.values() ) + 2
    if ( key_width + val_width ) < len( banner_top ):
        val_width = ( ( len( banner_top ) - key_width ) + 2 )

    print( f"{ RED }╔{ '═' * ( key_width + val_width + 4) }╗" )
    print( f"║{ WHITE }{ banner_top.center( val_width + key_width + 4, ' ' ) }{ RED }║")
    print( f"║{ WHITE }{'|__| |__| [__  |__|  \\_/  __ |    |__| |    |    [__'.center( val_width + key_width + 2, ' ' ) }  { RED }║")
    print( f"║{ WHITE }{'|  | |  | ___] |  |   |      |___ |  | |___ |___ ___]'.center( val_width + key_width + 4, ' ' ) }{ RED }║")
    print( f"║{' '.center( key_width + val_width + 4, ' ' ) }{ RED }║")
    print( f"║{ RED }{ 'An Import Address Table obfuscation utility for C'.center( val_width + key_width + 4, ' ' ) }{ RED }║")
    print( f"║{ 'Coded By: Wizardy0ga'.center( val_width + key_width + 4 ) }║")
    print( f"║{ f'Script Version: { SCRIPT_VERSION } | Template Version: { TEMPLATE_VERSION }'.center( key_width + val_width + 4 ) }║")
    print( f"║{' '.center( key_width + val_width + 4, ' ' ) }{ RED }║")

    # Create sections of the config
    top         = f"{ RED }╠{ '═' * ( key_width + 1 ) }╦{ '═' * ( val_width + 2) }╣"
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

# ---------------------------- Entry -----------------------
def main():
    args = parse_user_args()

    # --------------------- Entry ----------------------
    if args.version:
        hc_print(f' Module:   { SCRIPT_VERSION }\n\tTemplate: { TEMPLATE_VERSION }')
        exit()

    output_directory = os.path.join( os.getcwd(), args.outdir )

    # Get api calls from user
    api_calls = []
    user_api_call_imports = None
    if not args.file and not args.apicalls:
        hc_print('No api calls were given to the script. Specify a list of functions with --file or --apicalls. Use -h for further information')
        exit()
    if args.apicalls:
        user_api_call_imports = args.apicalls
    else:
        with open( args.file, 'r' ) as file:
            user_api_call_imports = file.read().split('\n')
            print(user_api_call_imports)
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
        hc_print(f'{ RED }hashycalls initialization failed with error: { END }{ e }')
        exit()

    # Print config
    args_dict = vars( args )
    for arg in [ 'apicalls', 'file' ]:
        del args_dict[ arg ]
    print_dict_table( args_dict )

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