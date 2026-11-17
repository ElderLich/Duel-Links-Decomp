#include "duel_exports.h"

// Steam target 66193d0d...: exported entry RVA 0x2060.
// Native body is mov eax, 0x1456b; ret, followed by INT3 alignment padding.
// This reconstructs the observed scalar return; the original source is unknown.
extern "C" __declspec(dllexport) unsigned int DLL_GetRevision() noexcept
{
    return 0x1456bu;
}
