# Import modules
import random
import subprocess
import shutil
import os
from hashycalls import HashyCalls

def compile( hashysource: HashyCalls ):
    """ Compile the source code & return status object from subprocess.run """

    # Create file paths & code for compiler
    temp_dir = os.path.join( os.path.dirname( os.path.abspath( __file__ ) ), 'temp' )
    compiler_file = os.path.join('temp','compiler.bat')
    compiler_code = f"""@echo off
call "C:\\Program Files\\Microsoft Visual Studio\\2022\\Community\\VC\\Auxiliary\\Build\\vcvars64.bat"
cd "{ temp_dir }"
cl main.c hashycalls.c
link.exe main.obj hashycalls.obj /OUT:HashycallsTest.exe
HashycallsTest.exe
"""
    # Write source code to directory
    os.makedirs( temp_dir, exist_ok = True )
    hashysource.header.write_to_dir( temp_dir )
    hashysource.source.write_to_dir( temp_dir )
    shutil.copyfile(os.path.join('..','src', 'hashycalls', 'rsrc', 'code', 'solution file', 'src', 'main.c'), os.path.join(temp_dir,'main.c'))
    with open( compiler_file, 'w' ) as temp_file:
        temp_file.write( compiler_code )
    
    # Run compiler script, remove temp dir & return status
    status = subprocess.run( ['cmd.exe', '/c', compiler_file ], check=False )
    shutil.rmtree( temp_dir )
    return status

def test_build_globals():
    """ Test hashycalls with global api pointer enabled """
    if compile( HashyCalls(
        apicalls        = [ 'GetCurrentProcessId', 'MessageBoxA' ]
        , globals       = True
        , api_list_name = 'hWin32'
        , algo          = 'djb2'
        , seed          = random.randint(1, 10000)
        , debug         = True
    ) ).returncode != 0:
        raise Exception( "Failed to compile and run test program." )
    
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
    ) ).returncode != 0:
        raise Exception( "Failed to compile and run test program." )
