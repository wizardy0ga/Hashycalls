DWORD HashStringDjb2A( _In_ LPCSTR String )
{
	ULONG   Hash    = HASH_SEED;
	INT     c       = 0;

	while (c = *String++)
		Hash = ((Hash << 5) + Hash) + c;

	return Hash;
}

DWORD HashStringDjb2W( _In_ LPCWSTR String )
{
	ULONG   Hash    = HASH_SEED;
	INT     c       = 0;

	while (c = *String++)
		Hash = ((Hash << 5) + Hash) + c;

	return Hash;
}