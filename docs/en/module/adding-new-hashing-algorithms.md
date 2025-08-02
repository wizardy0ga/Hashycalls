# Adding new hashing algorithms to hashycalls

This document describes the process for adding new hashing algorithms to hashycalls. In this example, we're adding the [MurmurHash3](https://github.com/vxunderground/VX-API/blob/main/VX-API/HashStringMurmur.cpp) algorithm from the [vx-api](https://github.com/vxunderground/VX-API).

## Step 1; Select a name for the algorithm.
We'll need to choose a name for the algorthm. This name will be used when setting the algorithm from the command line & initializing the **HashyCalls** object. For this example, we'll use the name **murmur**.

## Step 2; Create a hashing algorithm in C & Python
We'll need to choose a hashing algorithm & create corresponding functions in C and python. We'll start with the C side.

### Creating the C template
As previously stated, we've chosen to implement MurmurHash3 from the vx-api. The original source code from the vx-api is shown below.
###### HashStringMurmur.cpp from the VX-API
```c
#include "Win32Helper.h"

INT32 HashStringMurmurW(_In_ LPCWSTR String)
{
	INT  Length = (INT)StringLengthW(String);
	UINT32 hash = 0;
	PUINT32 Tmp;
	SIZE_T  Idx;
	UINT32  Cnt;

	if (Length > 3) 
  {
		Idx = Length >> 2;
		Tmp = (PUINT32)String;
    
		do {
			Cnt = *Tmp++;

			Cnt *= 0xcc9e2d51;
			Cnt  = (Cnt << 15) | (Cnt >> 17);
			Cnt *= 0x1b873593;

			hash ^= Cnt;
			hash  = (hash << 13) | (hash >> 19);
			hash  = (hash * 5) + 0xe6546b64;

		} while (--Idx);

		String = (PWCHAR)Tmp;
	}

	if (Length & 3) 
  {
		Idx    = Length & 3;
		Cnt    = 0;
		String = &String[Idx - 1];
    
		do {
			Cnt <<= 8;
			Cnt |= *String--;
  
		} while (--Idx);
    
		Cnt  *= 0xcc9e2d51;
		Cnt   = (Cnt << 15) | (Cnt >> 17);
		Cnt  *= 0x1b873593;
		hash ^= Cnt;
	}

	hash ^= Length;
	hash ^= hash >> 16;
	hash *= 0x85ebca6b;
	hash ^= hash >> 13;
	hash *= 0xc2b2ae35;
	hash ^= hash >> 16;

	return hash;
}

INT32 HashStringMurmurA(_In_ LPCSTR String)
{
	INT  Length = (INT)StringLengthA(String);
	UINT32 hash = 0;
	PUINT32 Tmp;
	SIZE_T  Idx;
	UINT32  Cnt;

	if (Length > 3) 
  {
		Idx = Length >> 2;
		Tmp = (PUINT32)String;
    
		do {
			Cnt = *Tmp++;

			Cnt *= 0xcc9e2d51;
			Cnt = (Cnt << 15) | (Cnt >> 17);
			Cnt *= 0x1b873593;

			hash ^= Cnt;
			hash = (hash << 13) | (hash >> 19);
			hash = (hash * 5) + 0xe6546b64;

		} while (--Idx);

		String = (PCHAR)Tmp;
	}

	if (Length & 3) 
  {
		Idx = Length & 3;
		Cnt = 0;
		String = &String[Idx - 1];
    
		do {
			Cnt <<= 8;
			Cnt |= *String--;

		} while (--Idx);

		Cnt *= 0xcc9e2d51;
		Cnt = (Cnt << 15) | (Cnt >> 17);
		Cnt *= 0x1b873593;
		hash ^= Cnt;
	}

	hash ^= Length;
	hash ^= hash >> 16;
	hash *= 0x85ebca6b;
	hash ^= hash >> 13;
	hash *= 0xc2b2ae35;
	hash ^= hash >> 16;

	return hash;

}
```

We'll need to make this template compatible with hashycalls. For any template to be compatible, it will need to have the following:
- Create two hashing functions, one for ANSI and for Wide characters
- Set the algorithms seed to the **HASH_ALGO** macro

For this template specifically, we have converted the **StringLength** function to inline code as well. 

###### Hashycalls compatible hashing algorithm
```c
INT32 HashStringMurmurW(_In_ LPCWSTR String)
{
	INT  Length = 0
	UINT32 hash = HASH_SEED;
	PUINT32 Tmp;
	SIZE_T  Idx;
	UINT32  Cnt;
    LPCWSTR String2;
    
    for (String2 = String; *String2; ++String2);
	Length = (String2 - String)
    
	if (Length > 3) 
  	{
		Idx = Length >> 2;
		Tmp = (PUINT32)String;
    
		do {
			Cnt = *Tmp++;

			Cnt *= 0xcc9e2d51;
			Cnt  = (Cnt << 15) | (Cnt >> 17);
			Cnt *= 0x1b873593;

			hash ^= Cnt;
			hash  = (hash << 13) | (hash >> 19);
			hash  = (hash * 5) + 0xe6546b64;

		} while (--Idx);

		String = (PWCHAR)Tmp;
	}

	if (Length & 3) 
  	{
		Idx    = Length & 3;
		Cnt    = 0;
		String = &String[Idx - 1];
    
		do {
			Cnt <<= 8;
			Cnt |= *String--;
  
		} while (--Idx);
    
		Cnt  *= 0xcc9e2d51;
		Cnt   = (Cnt << 15) | (Cnt >> 17);
		Cnt  *= 0x1b873593;
		hash ^= Cnt;
	}

	hash ^= Length;
	hash ^= hash >> 16;
	hash *= 0x85ebca6b;
	hash ^= hash >> 13;
	hash *= 0xc2b2ae35;
	hash ^= hash >> 16;

	return hash;
}

INT32 HashStringMurmurA(_In_ LPCSTR String)
{
	INT  Length = 0
	UINT32 hash = HASH_SEED;
	PUINT32 Tmp;
	SIZE_T  Idx;
	UINT32  Cnt;
    LPCSTR String2;

    for (String2 = String; *String2; ++String2);
    Length = (String2 - String);

	if (Length > 3) 
  {
		Idx = Length >> 2;
		Tmp = (PUINT32)String;
    
		do {
			Cnt = *Tmp++;

			Cnt *= 0xcc9e2d51;
			Cnt = (Cnt << 15) | (Cnt >> 17);
			Cnt *= 0x1b873593;

			hash ^= Cnt;
			hash = (hash << 13) | (hash >> 19);
			hash = (hash * 5) + 0xe6546b64;

		} while (--Idx);

		String = (PCHAR)Tmp;
	}

	if (Length & 3) 
  {
		Idx = Length & 3;
		Cnt = 0;
		String = &String[Idx - 1];
    
		do {
			Cnt <<= 8;
			Cnt |= *String--;

		} while (--Idx);

		Cnt *= 0xcc9e2d51;
		Cnt = (Cnt << 15) | (Cnt >> 17);
		Cnt *= 0x1b873593;
		hash ^= Cnt;
	}

	hash ^= Length;
	hash ^= hash >> 16;
	hash *= 0x85ebca6b;
	hash ^= hash >> 13;
	hash *= 0xc2b2ae35;
	hash ^= hash >> 16;

	return hash;
}
```

Once the template is finished, add it to the [templates](../../../src/hashycalls/rsrc/code/templates/) directory. In this example, we've chosen the file name **murmur.c**.

###### Adding the hashing algorithm template
![adding-hash-template](../../img/adding-hash-template.png)

### Creating the python function
Now we'll need a corresponding python function which produces the same hash as its C counterpart.

> [!IMPORTANT]  
> This function needs to be compatible with the HashyCalls object. Make sure it's compatible by performing the following steps:
> - Add **self** object reference to parameter
> - Return the hash as a hex string denoted by **0x**
> - Set the seed to self.seed

###### MurmurHash3 function in python
```py
def hash_murmur( self, string: str ) -> str:
    """ Hash a string with MurmurHash3 algo """
    string = string.encode()
    length = len(string)
    Hash = self.seed
    if length > 3:
        idx = length >> 2
        for i in range(idx):
            start = i * 4
            cnt = int.from_bytes(string[start:start+4], byteorder='little')
            cnt = (cnt * 0xcc9e2d51) & 0xffffffff
            cnt = ((cnt << 15) | (cnt >> 17)) & 0xffffffff
            cnt = (cnt * 0x1b873593) & 0xffffffff
            Hash ^= cnt
            Hash = ((Hash << 13) | (Hash >> 19)) & 0xffffffff
            Hash = ((Hash * 5) + 0xe6546b64) & 0xffffffff
    remaining = length & 3
    if remaining:
        cnt = 0
        start_pos = (length >> 2) * 4 + remaining - 1
        for i in range(remaining):
            cnt = (cnt << 8) & 0xffffffff
            cnt |= string[start_pos - i]
        cnt = (cnt * 0xcc9e2d51) & 0xffffffff
        cnt = ((cnt << 15) | (cnt >> 17)) & 0xffffffff
        cnt = (cnt * 0x1b873593) & 0xffffffff
        Hash ^= cnt
    Hash ^= length
    Hash ^= Hash >> 16
    Hash = (Hash * 0x85ebca6b) & 0xffffffff
    Hash ^= Hash >> 13
    Hash = (Hash * 0xc2b2ae35) & 0xffffffff
    Hash ^= Hash >> 16
    return "0x%X" % Hash
```

## Step 3; Modiying the module source code
In this step, we'll need to make some modifications to [core.py](../../../src/hashycalls/core.py) to make the new hashing algorithm compatible with wizardcalls.

### Add global variable for the C template file path
We'll need to add a global variable for the C template file path that was created in step 2. Add this to the top of the file as shown below.

###### Adding the template filepath
![adding-template-filepath](../../img/adding-template-filepath.png)

### Adding the python hashing algorithm to HashycallsFile object
In step 2, we created a python function for the hashing algorithm. This algorithm needs to be implemented as a method of the **HashycallsFile** object.

###### Adding the new algorithm as a method of HashycallsFile
![add-algo-to-obj](../../img/add-algo-to-obj.png)

### Adding new algorithm the initialization routine
Now we'll need to add the algorithm to the initializatin routine. This routine is a match statement in the constructor function of **HashycallsFile**.

> [!IMPORTANT]   
> In step 1, we created a name for the hashing algorithm. This name needs to be used as the case for the match statement as shown below.

To implement the algorithm, follow these steps:
- Set **hash_function** to the name of the new hashing algorithm method
- Set **hash_function_file** to the filepath fo the template
- Set **hash_function_name** to the name of the hashing function in the C template. **Remove the A & W char type identifier from the end of the function**.

###### Updating the initialization routine
![update-init-routine](../../img/update-init-routine.png)

## Step 4; Testing the hashing algorithms
We'll need to test the new algorithm to ensure it's working correctly. The test consists of generating a test executable with hashycalls & executing it. If it executes properly, then the hashing algorithm is working correctly.

Start by updating the **test_hashing_algos** function in [test_build.py](../../../tests/test_build.py). Add the name of your new algorithm to the array. This is the name you chose in step 1.

###### Updating the hashing algorithm test
![updating-algorithm-test](../../img/updating-algorithm-test.png)

When the testing function has been updated, we'll need to run the test. Navigate to the [tests](../../../tests/) directory and execute the command below.
```
pytest -s .\test_build.py::test_hash_algos
```

###### Running the hashing algorithm test
![running-the-algorithm-test](../../img/running-the-algorithm-test.gif)

You'll know the test passed if you see a message box appear showing the PID of the newly spawned process. If the test did not pass, go back and troubleshoot the error.

## Step 5; Updating the command line interface
When everythings working, we can add the argument to the command line arguments in [args.py](../../../src/hashycalls/args.py).

Locate the **--algo** argument and the new algorithm. Use the name you defined in step 1.

###### Adding the hashing alg argument
![adding-new-hashing-algorithm-arg](../../img/adding-new-hashing-algorithm-arg.png)