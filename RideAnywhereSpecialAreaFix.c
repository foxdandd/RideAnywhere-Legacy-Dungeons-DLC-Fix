#define WIN32_LEAN_AND_MEAN
#include <windows.h>

/*
 * The versioned RideAnywhere DLL can fail its one-shot AOB scan during the
 * early ME3 attach window. This helper owns both runtime gates and retries
 * until the game image is ready. On 1.16.2 the original DLL remains the
 * owner when it is loaded; on 1.17 the profile omits it and this helper owns
 * both gates.
 */

static volatile LONG g_status = 0;

__declspec(dllexport) LONG RideAnywhereSpecialAreaFixStatus(void)
{
    return g_status;
}

static int bytes_equal(const BYTE *left, const BYTE *right, SIZE_T size)
{
    SIZE_T i;
    for (i = 0; i < size; ++i) {
        if (left[i] != right[i]) {
            return 0;
        }
    }
    return 1;
}

static int find_unique_gate(
    HMODULE image,
    const BYTE *signature,
    SIZE_T signature_size,
    const BYTE *patched_signature,
    SIZE_T patched_signature_size,
    BYTE **match_out,
    DWORD *matches_out,
    DWORD *patched_matches_out)
{
    IMAGE_DOS_HEADER *dos;
    IMAGE_NT_HEADERS64 *nt;
    IMAGE_SECTION_HEADER *section;
    BYTE *match = NULL;
    DWORD matches = 0;
    DWORD patched_matches = 0;
    WORD i;

    dos = (IMAGE_DOS_HEADER *)image;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) {
        return -1;
    }
    nt = (IMAGE_NT_HEADERS64 *)((BYTE *)image + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE ||
        nt->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
        return -2;
    }

    section = IMAGE_FIRST_SECTION(nt);
    for (i = 0; i < nt->FileHeader.NumberOfSections; ++i, ++section) {
        BYTE *begin;
        SIZE_T size;
        SIZE_T offset;
        if ((section->Characteristics & IMAGE_SCN_MEM_EXECUTE) == 0) {
            continue;
        }
        begin = (BYTE *)image + section->VirtualAddress;
        size = section->Misc.VirtualSize;
        if (size < signature_size || size < patched_signature_size) {
            continue;
        }
        for (offset = 0; offset <= size - signature_size; ++offset) {
            if (bytes_equal(begin + offset, signature, signature_size)) {
                match = begin + offset;
                ++matches;
            }
        }
        for (offset = 0; offset <= size - patched_signature_size; ++offset) {
            if (bytes_equal(begin + offset, patched_signature, patched_signature_size)) {
                ++patched_matches;
            }
        }
    }

    *match_out = match;
    *matches_out = matches;
    *patched_matches_out = patched_matches;
    return 0;
}

static int write_gate_patch(BYTE *target, const BYTE *replacement, SIZE_T size)
{
    DWORD old_protection;
    DWORD ignored;
    SIZE_T i;

    if (!VirtualProtect(target, size, PAGE_EXECUTE_READWRITE, &old_protection)) {
        return 0;
    }
    for (i = 0; i < size; ++i) {
        target[i] = replacement[i];
    }
    FlushInstructionCache(GetCurrentProcess(), target, size);
    VirtualProtect(target, size, old_protection, &ignored);
    return 1;
}

static int patch_one_gate(
    HMODULE image,
    const BYTE *signature,
    SIZE_T signature_size,
    const BYTE *patched_signature,
    SIZE_T patched_signature_size,
    SIZE_T patch_offset,
    const BYTE *replacement,
    SIZE_T replacement_size)
{
    BYTE *match = NULL;
    DWORD matches = 0;
    DWORD patched_matches = 0;
    int result;

    result = find_unique_gate(
        image,
        signature,
        signature_size,
        patched_signature,
        patched_signature_size,
        &match,
        &matches,
        &patched_matches);
    if (result != 0) {
        return result;
    }
    if (matches == 0 && patched_matches == 1) {
        return 1;
    }
    if (matches != 1 || match == NULL) {
        return -3;
    }
    if (!write_gate_patch(match + patch_offset, replacement, replacement_size)) {
        return -4;
    }
    return 1;
}

static DWORD WINAPI apply_patch(LPVOID unused)
{
    static const BYTE primary_signature[] = {
        0x80, 0x78, 0x36, 0x00, 0x0F, 0x95, 0xC0,
        0x40, 0xB7, 0x01, 0x88, 0x06
    };
    static const BYTE primary_patched_signature[] = {
        0xC6, 0x40, 0x36, 0x00, 0xB0, 0x00, 0x90,
        0x40, 0xB7, 0x01, 0x88, 0x06
    };
    static const BYTE primary_replacement[] = {
        0xC6, 0x40, 0x36, 0x00, 0xB0, 0x00, 0x90
    };
    static const BYTE special_signature[] = {
        0x80, 0x79, 0x36, 0x00, 0x0F, 0x95, 0xC0,
        0x48, 0x83, 0xC4, 0x28, 0xC3
    };
    static const BYTE special_patched_signature[] = {
        0x80, 0x79, 0x36, 0x00, 0x30, 0xC0, 0x90,
        0x48, 0x83, 0xC4, 0x28, 0xC3
    };
    static const BYTE special_replacement[] = {0x30, 0xC0, 0x90};
    HMODULE image;
    int primary_result;
    int special_result;
    DWORD attempt;

    (void)unused;
    image = GetModuleHandleA(NULL);
    if (image == NULL) {
        g_status = -1;
        return 1;
    }

    /* Keep the established 1.16.2 load order untouched. */
    if (GetModuleHandleA("RideAnywhere.dll") != NULL) {
        g_status = 1;
        OutputDebugStringA("RideAnywhereSpecialAreaFix: original RideAnywhere DLL is active; helper skipped.\n");
        return 0;
    }

    for (attempt = 0; attempt < 300; ++attempt) {
        primary_result = patch_one_gate(
            image,
            primary_signature,
            sizeof(primary_signature),
            primary_patched_signature,
            sizeof(primary_patched_signature),
            0,
            primary_replacement,
            sizeof(primary_replacement));
        special_result = patch_one_gate(
            image,
            special_signature,
            sizeof(special_signature),
            special_patched_signature,
            sizeof(special_patched_signature),
            4,
            special_replacement,
            sizeof(special_replacement));
        if (primary_result > 0 && special_result > 0) {
            g_status = 1;
            OutputDebugStringA("RideAnywhereSpecialAreaFix: both Torrent gates disabled.\n");
            return 0;
        }
        Sleep(100);
    }

    g_status = -3;
    OutputDebugStringA("RideAnywhereSpecialAreaFix: Torrent gate signatures were not ready or unique.\n");
    return 3;
}

BOOL WINAPI DllMain(HINSTANCE instance, DWORD reason, LPVOID reserved)
{
    (void)reserved;
    if (reason == DLL_PROCESS_ATTACH) {
        HANDLE thread;
        DisableThreadLibraryCalls(instance);
        thread = CreateThread(NULL, 0, apply_patch, NULL, 0, NULL);
        if (thread != NULL) {
            CloseHandle(thread);
        } else {
            g_status = -5;
        }
    }
    return TRUE;
}
