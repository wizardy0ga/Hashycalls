# Import modules
import random
import subprocess
import shutil
import os
from pytest import fail
from hashycalls import HashyCalls

def compile( hashysource: HashyCalls ):
    """ Compile the source code & return status object from subprocess.run """
    # Check for visual studio vars file to intiailize dev environmen
    vcvars_file = False
    for file in [
        "Microsoft Visual Studio\\2022\\Enterprise\\VC\\Auxiliary\\Build\\vcvars64.bat",
        "Microsoft Visual Studio\\2022\\Community\\VC\\Auxiliary\\Build\\vcvars64.bat",
        "Microsoft Visual Studio\\2022\\Professional\\VC\\Auxiliary\\Build\\vcvars64.bat"
    ]:
        file = os.path.join( os.getenv( 'ProgramFiles' ), file )
        if os.path.exists( file ):
            vcvars_file = file
            break
    if not vcvars_file:
        fail( "Could not locate visual studio on host." )

    # Create file paths & code for compiler
    temp_dir      = os.path.join( os.path.dirname( os.path.abspath( __file__ ) ), 'temp' )
    main_source   = os.path.join( '..', 'src', 'hashycalls', 'rsrc', 'code', 'solution file', 'src', 'main.c' )
    main_dest     = os.path.join( temp_dir, 'main.c' )
    compiler_file = os.path.join( 'temp', 'compiler.bat' )
    compiler_code = f"""@echo off
call {vcvars_file}
cd "{ temp_dir }"
cl main.c hashycalls.c
link.exe main.obj hashycalls.obj /OUT:HashycallsTest.exe
HashycallsTest.exe
"""
    # Write source code to directory
    os.makedirs( temp_dir, exist_ok = True )
    hashysource.header.write_to_dir( temp_dir )
    hashysource.source.write_to_dir( temp_dir )
    with open( main_source, 'r' ) as source_file:
        data = source_file.read().replace( '# include "../src/hashycalls.h"', '# include "hashycalls.h""' )
    with open( main_dest, 'w') as dest_file:
        dest_file.write(data)
    with open( compiler_file, 'w' ) as compiler_script:
        compiler_script.write( compiler_code )

    # Run compiler script, remove temp dir & return status
    status = subprocess.run( ['cmd.exe', '/c', compiler_file ], check=False, capture_output=True ).returncode
    return True if status == 0 else False


def test_build_globals():
    """ Test hashycalls with global api pointer enabled """
    if compile( HashyCalls(
        apicalls        = [ 'GetCurrentProcessId', 'MessageBoxA' ]
        , globals       = True
        , api_list_name = 'hWin32'
        , algo          = 'djb2'
        , seed          = random.randint(1, 10000)
        , debug         = True
    )):
        print( 'Passed global api call list test!' )
    else:
        fail( 'Failed to compile program with global api call list enabled.' )


def test_build_no_globals():
    """ Test hashycalls with NO global api pointer enabled """
    # Create hashycalls source object
    if compile( HashyCalls(
        apicalls        = [ 'GetCurrentProcessId', 'MessageBoxA' ]
        , globals       = False
        , api_list_name = 'hWin32'
        , algo          = 'djb2'
        , seed          = random.randint(1, 10000)
        , debug         = True
    )):
        print( 'Passed local api call list test!' )
    else:
        fail( 'Failed to compile program with local api call list.' )


def test_hash_algos():
    """ Test the hashycalls hashing algorithms """
    for algo in [ 'sdbm', 'djb2', 'murmur' ]:
        if compile( HashyCalls(
            apicalls        = [ 'GetCurrentProcessId', 'MessageBoxA' ]
            , globals       = True
            , api_list_name = 'hWin32'
            , algo          = algo
            , seed          = random.randint(1, 10000)
            , debug         = True
        )):
            print( f'Passed { algo } hashing algorithm test' )
        else:
            fail( f'Failed { algo } hashing algorithm test' )