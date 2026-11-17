#pragma once

static_assert(sizeof(unsigned int) == 4, "The native revision result is 32 bits.");
extern "C" __declspec(dllexport) unsigned int DLL_GetRevision() noexcept;
