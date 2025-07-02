# Import modules
from os import remove, path
from hashycalls import HashyCalls

# Create hashycalls source object
hashysource = HashyCalls(
    apicalls = ['OpenProcess', 'VirtualAllocEx', 'WriteProcessMemory', 'CreateRemoteThread']
    , globals = True
    , api_list_name = 'hWin32'
    , algo = 'djb2'
    , seed  = 1000
    , debug = True
)

# Write source code to directory
current_dir = path.dirname( path.abspath( __file__ ) )
hashysource.header.write_to_dir( current_dir )
hashysource.source.write_to_dir( current_dir )
print(f"Wrote { hashysource.header.filename } to { hashysource.header.path_on_disk }")
print(f"Wrote { hashysource.source.filename } to { hashysource.source.path_on_disk }")

# Remote source code from directory
remove( hashysource.header.path_on_disk )
remove( hashysource.source.path_on_disk )
print(f"Removed { hashysource.source.path_on_disk }")
print(f"Removed { hashysource.source.path_on_disk }")
