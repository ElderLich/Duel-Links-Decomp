// Buffer allocation queries for the pinned Steam target.
// The client declarations distinguish a signed backup size from an unsigned
// card-rarity size. Both results count bytes, not cards or serialized fields.
// The internal buffer layouts remain unresolved.

static_assert(sizeof(int) == 4, "The native backup-size result is 32 bits.");
static_assert(sizeof(unsigned int) == 4, "The native rarity-buffer result is 32 bits.");

extern "C" __declspec(dllexport) int DLL_DuelGetBackupSize() noexcept
{
    return 3520264;
}

extern "C" __declspec(dllexport) unsigned int DLL_CardRareGetBufferSize() noexcept
{
    return 4096u;
}
