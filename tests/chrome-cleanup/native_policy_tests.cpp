// Native Windows tests for modules extracted from the submitted mod.
// HKCU and HKLM are redirected only in this disposable test process.
// No real Chrome policy key is read or changed.
#include <windows.h>
#include <shellapi.h>
#include <sddl.h>
#include <aclapi.h>
#include <objbase.h>
#include <userenv.h>

#include <algorithm>
#include <array>
#include <atomic>
#include <cstdarg>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <cwchar>
#include <cwctype>
#include <exception>
#include <filesystem>
#include <map>
#include <memory>
#include <mutex>
#include <new>
#include <set>
#include <stdexcept>
#include <string>
#include <string_view>
#include <thread>
#include <unordered_map>
#include <utility>
#include <vector>

// Observe only the exact mod modules below. Fixture setup uses the real APIs.
// This records calls rather than attempting to take a non-recursive lock again.
thread_local unsigned g_testBookkeepingDepth = 0;
std::atomic<unsigned> g_testIoUnderLock{0};
std::atomic<unsigned> g_testAllocationUnderLock{0};
std::atomic<unsigned> g_testDeallocationUnderLock{0};
std::atomic<const char*> g_testFirstLockedIo{nullptr};
std::atomic<unsigned> g_testHiveLoads{0};
enum class TestSlowPoint { None, HiveLoad, EnumerateValue, NativeClose, SignalEvent };
std::atomic<TestSlowPoint> g_testSlowPoint{TestSlowPoint::None};
HANDLE g_testSlowEntered = nullptr;
HANDLE g_testSlowRelease = nullptr;
std::atomic<bool> g_testSlowTimeout{false};
std::atomic<HKEY> g_testFailCloseOnce{nullptr};
std::atomic<unsigned> g_testFailedCloses{0};
std::atomic<LSTATUS> g_testEnumFaultCode{ERROR_SUCCESS};
std::atomic<unsigned> g_testEnumFaultsRemaining{0};
std::atomic<unsigned> g_testEnumFaultsInjected{0};
std::atomic<unsigned> g_testLogCount{0};
std::atomic<DWORD> g_testUnknownProcessPid{0};

static void TestObserveIo(const char* name) {
    if (g_testBookkeepingDepth) {
        ++g_testIoUnderLock;
        const char* absent = nullptr;
        g_testFirstLockedIo.compare_exchange_strong(absent, name);
    }
    const bool hiveLoad = std::strcmp(name, "RegLoadAppKeyW") == 0;
    if (hiveLoad) ++g_testHiveLoads;
    auto selected = hiveLoad ? TestSlowPoint::HiveLoad :
                    std::strcmp(name, "RegEnumValueW") == 0 ? TestSlowPoint::EnumerateValue :
                    std::strcmp(name, "RegCloseKey") == 0 ? TestSlowPoint::NativeClose :
                    std::strcmp(name, "SetEvent") == 0 ? TestSlowPoint::SignalEvent :
                    TestSlowPoint::None;
    if (selected != TestSlowPoint::None &&
        g_testSlowPoint.compare_exchange_strong(selected, TestSlowPoint::None)) {
        SetEvent(g_testSlowEntered);
        if (WaitForSingleObject(g_testSlowRelease, 10000) != WAIT_OBJECT_0) {
            g_testSlowTimeout = true;
        }
    }
}

template<auto Function, typename... Args>
decltype(auto) TestObservedNativeCall(const char* name, Args&&... args) {
    const auto error = GetLastError();
    TestObserveIo(name);
    SetLastError(error);
    return Function(std::forward<Args>(args)...);
}

static void WINAPI TestAcquireExclusive(PSRWLOCK lock) {
    AcquireSRWLockExclusive(lock);
    ++g_testBookkeepingDepth;
}
static void WINAPI TestReleaseExclusive(PSRWLOCK lock) {
    --g_testBookkeepingDepth;
    ReleaseSRWLockExclusive(lock);
}
[[maybe_unused]] static void WINAPI TestAcquireShared(PSRWLOCK lock) {
    AcquireSRWLockShared(lock);
    ++g_testBookkeepingDepth;
}
[[maybe_unused]] static void WINAPI TestReleaseShared(PSRWLOCK lock) {
    --g_testBookkeepingDepth;
    ReleaseSRWLockShared(lock);
}
static LSTATUS WINAPI TestObservedRegOpen(HKEY key, LPCWSTR path, DWORD options,
                                         REGSAM access, PHKEY output) {
    return TestObservedNativeCall<&RegOpenKeyExW>(
        "RegOpenKeyExW", key, path, options, access, output);
}
static LSTATUS WINAPI TestObservedRegClose(HKEY key) {
    HKEY requested = key;
    if (key && g_testFailCloseOnce.compare_exchange_strong(requested, nullptr)) {
        TestObserveIo("RegCloseKey");
        ++g_testFailedCloses;
        return ERROR_ACCESS_DENIED;
    }
    return TestObservedNativeCall<&RegCloseKey>("RegCloseKey", key);
}
static LSTATUS WINAPI TestObservedRegEnumValue(
    HKEY key, DWORD index, LPWSTR name, LPDWORD chars, LPDWORD reserved,
    LPDWORD type, LPBYTE data, LPDWORD bytes) {
    auto remaining = g_testEnumFaultsRemaining.load();
    while (remaining) {
        if (g_testEnumFaultsRemaining.compare_exchange_weak(remaining, remaining - 1)) {
            TestObserveIo("RegEnumValueW");
            ++g_testEnumFaultsInjected;
            return g_testEnumFaultCode.load();
        }
    }
    return TestObservedNativeCall<&RegEnumValueW>(
        "RegEnumValueW", key, index, name, chars, reserved, type, data, bytes);
}
static HANDLE WINAPI TestObservedOpenProcess(DWORD access, BOOL inherit, DWORD pid) {
    if (pid && pid == g_testUnknownProcessPid.load()) {
        TestObserveIo("OpenProcess");
        SetLastError(ERROR_ACCESS_DENIED);
        return nullptr;
    }
    return TestObservedNativeCall<&OpenProcess>("OpenProcess", access, inherit, pid);
}

// Fault injection for a tracked relative-open bookkeeping allocation. The
// native RegOpenKeyExW call allocates through Windows, not global C++ new.
std::atomic<bool> g_testFailNextAllocation{false};
void* operator new(size_t size) {
    if (g_testBookkeepingDepth) ++g_testAllocationUnderLock;
    if (g_testFailNextAllocation.exchange(false)) {
        throw std::bad_alloc();
    }
    if (void* memory = std::malloc(size ? size : 1)) {
        return memory;
    }
    throw std::bad_alloc();
}
void* operator new[](size_t size) {
    return ::operator new(size);
}
void operator delete(void* memory) noexcept {
    if (memory && g_testBookkeepingDepth) ++g_testDeallocationUnderLock;
    std::free(memory);
}
void operator delete[](void* memory) noexcept {
    ::operator delete(memory);
}
void operator delete(void* memory, size_t) noexcept {
    ::operator delete(memory);
}
void operator delete[](void* memory, size_t) noexcept {
    ::operator delete(memory);
}

std::wstring g_testStorage;
std::vector<std::wstring> g_testKeepSites;

void Wh_Log(PCWSTR format, ...) {
    TestObserveIo("Wh_Log");
    ++g_testLogCount;
    wchar_t buffer[2048]{};
    // Windhawk uses Microsoft's wide-format %s convention. This harness is
    // compiled against the MinGW standard formatter, which uses %ls instead.
    std::wstring nativeFormat(format);
    for (size_t offset = 0; (offset = nativeFormat.find(L"%s", offset)) != std::wstring::npos;) {
        nativeFormat.replace(offset, 2, L"%ls");
        offset += 3;
    }
    va_list args;
    va_start(args, format);
    vswprintf(buffer, std::size(buffer), nativeFormat.c_str(), args);
    va_end(args);
    fputws(L"MOD: ", stderr);
    fputws(buffer, stderr);
    fputws(L"\n", stderr);
}

size_t Wh_GetModStoragePath(PWSTR output, size_t capacity) {
    TestObserveIo("Wh_GetModStoragePath");
    if (!output || capacity <= g_testStorage.size()) {
        return 0;
    }
    std::copy(g_testStorage.begin(), g_testStorage.end(), output);
    output[g_testStorage.size()] = L'\0';
    return g_testStorage.size();
}

PCWSTR Wh_GetStringSetting(PCWSTR, int index) {
    const auto value = index >= 0 && static_cast<size_t>(index) < g_testKeepSites.size()
                           ? g_testKeepSites[static_cast<size_t>(index)]
                           : std::wstring{};
    auto* result = new wchar_t[value.size() + 1];
    std::copy(value.begin(), value.end(), result);
    result[value.size()] = L'\0';
    return result;
}

namespace WindhawkUtils {
class StringSetting {
public:
    explicit StringSetting(PCWSTR value) : value_(value) {}
    ~StringSetting() { delete[] value_; }
    StringSetting(const StringSetting&) = delete;
    StringSetting& operator=(const StringSetting&) = delete;
    PCWSTR get() const { return value_; }
private:
    PCWSTR value_;
};
}  // namespace WindhawkUtils

namespace {
#define AcquireSRWLockExclusive TestAcquireExclusive
#define ReleaseSRWLockExclusive TestReleaseExclusive
#define AcquireSRWLockShared TestAcquireShared
#define ReleaseSRWLockShared TestReleaseShared
#define RegOpenKeyExW TestObservedRegOpen
#define RegCloseKey TestObservedRegClose
#define RegLoadAppKeyW(...) TestObservedNativeCall<&::RegLoadAppKeyW>("RegLoadAppKeyW", __VA_ARGS__)
#define RegCreateKeyExW(...) TestObservedNativeCall<&::RegCreateKeyExW>("RegCreateKeyExW", __VA_ARGS__)
#define RegSetValueExW(...) TestObservedNativeCall<&::RegSetValueExW>("RegSetValueExW", __VA_ARGS__)
#define RegDeleteTreeW(...) TestObservedNativeCall<&::RegDeleteTreeW>("RegDeleteTreeW", __VA_ARGS__)
#define RegDeleteValueW(...) TestObservedNativeCall<&::RegDeleteValueW>("RegDeleteValueW", __VA_ARGS__)
#define RegEnumKeyExW(...) TestObservedNativeCall<&::RegEnumKeyExW>("RegEnumKeyExW", __VA_ARGS__)
#define RegEnumValueW TestObservedRegEnumValue
#define RegQueryInfoKeyW(...) TestObservedNativeCall<&::RegQueryInfoKeyW>("RegQueryInfoKeyW", __VA_ARGS__)
#define RegQueryValueExW(...) TestObservedNativeCall<&::RegQueryValueExW>("RegQueryValueExW", __VA_ARGS__)
#define CreateDirectoryW(...) TestObservedNativeCall<&::CreateDirectoryW>("CreateDirectoryW", __VA_ARGS__)
#define CreateFileW(...) TestObservedNativeCall<&::CreateFileW>("CreateFileW", __VA_ARGS__)
#define DeleteFileW(...) TestObservedNativeCall<&::DeleteFileW>("DeleteFileW", __VA_ARGS__)
#define RemoveDirectoryW(...) TestObservedNativeCall<&::RemoveDirectoryW>("RemoveDirectoryW", __VA_ARGS__)
#define GetFileAttributesW(...) TestObservedNativeCall<&::GetFileAttributesW>("GetFileAttributesW", __VA_ARGS__)
#define GetFileInformationByHandle(...) TestObservedNativeCall<&::GetFileInformationByHandle>("GetFileInformationByHandle", __VA_ARGS__)
#define SetFileInformationByHandle(...) TestObservedNativeCall<&::SetFileInformationByHandle>("SetFileInformationByHandle", __VA_ARGS__)
#define FindFirstFileW(...) TestObservedNativeCall<&::FindFirstFileW>("FindFirstFileW", __VA_ARGS__)
#define FindNextFileW(...) TestObservedNativeCall<&::FindNextFileW>("FindNextFileW", __VA_ARGS__)
#define FindClose(...) TestObservedNativeCall<&::FindClose>("FindClose", __VA_ARGS__)
#define GetSecurityInfo(...) TestObservedNativeCall<&::GetSecurityInfo>("GetSecurityInfo", __VA_ARGS__)
#define OpenProcess TestObservedOpenProcess
#define WaitForSingleObject(...) TestObservedNativeCall<&::WaitForSingleObject>("WaitForSingleObject", __VA_ARGS__)
#define OpenProcessToken(...) TestObservedNativeCall<&::OpenProcessToken>("OpenProcessToken", __VA_ARGS__)
#define GetTokenInformation(...) TestObservedNativeCall<&::GetTokenInformation>("GetTokenInformation", __VA_ARGS__)
#define ConvertSidToStringSidW(...) TestObservedNativeCall<&::ConvertSidToStringSidW>("ConvertSidToStringSidW", __VA_ARGS__)
#define ConvertStringSecurityDescriptorToSecurityDescriptorW(...) TestObservedNativeCall<&::ConvertStringSecurityDescriptorToSecurityDescriptorW>("ConvertStringSecurityDescriptorToSecurityDescriptorW", __VA_ARGS__)
#define CoCreateGuid(...) TestObservedNativeCall<&::CoCreateGuid>("CoCreateGuid", __VA_ARGS__)
#define StringFromGUID2(...) TestObservedNativeCall<&::StringFromGUID2>("StringFromGUID2", __VA_ARGS__)
#define CompareStringOrdinal(...) TestObservedNativeCall<&::CompareStringOrdinal>("CompareStringOrdinal", __VA_ARGS__)
#define EqualSid(...) TestObservedNativeCall<&::EqualSid>("EqualSid", __VA_ARGS__)
#define CloseHandle(...) TestObservedNativeCall<&::CloseHandle>("CloseHandle", __VA_ARGS__)
#define DuplicateHandle(...) TestObservedNativeCall<&::DuplicateHandle>("DuplicateHandle", __VA_ARGS__)
#define SetEvent(...) TestObservedNativeCall<&::SetEvent>("SetEvent", __VA_ARGS__)
#define LocalFree(...) TestObservedNativeCall<&::LocalFree>("LocalFree", __VA_ARGS__)
#include "policy_overlay.inc"
#include "mod_settings.inc"
#include "policy_refresh.inc"
#undef AcquireSRWLockExclusive
#undef ReleaseSRWLockExclusive
#undef AcquireSRWLockShared
#undef ReleaseSRWLockShared
#undef RegOpenKeyExW
#undef RegCloseKey
#undef RegLoadAppKeyW
#undef RegCreateKeyExW
#undef RegSetValueExW
#undef RegDeleteTreeW
#undef RegDeleteValueW
#undef RegEnumKeyExW
#undef RegEnumValueW
#undef RegQueryInfoKeyW
#undef RegQueryValueExW
#undef CreateDirectoryW
#undef CreateFileW
#undef DeleteFileW
#undef RemoveDirectoryW
#undef GetFileAttributesW
#undef GetFileInformationByHandle
#undef SetFileInformationByHandle
#undef FindFirstFileW
#undef FindNextFileW
#undef FindClose
#undef GetSecurityInfo
#undef OpenProcess
#undef WaitForSingleObject
#undef OpenProcessToken
#undef GetTokenInformation
#undef ConvertSidToStringSidW
#undef ConvertStringSecurityDescriptorToSecurityDescriptorW
#undef CoCreateGuid
#undef StringFromGUID2
#undef CompareStringOrdinal
#undef EqualSid
#undef CloseHandle
#undef DuplicateHandle
#undef SetEvent
#undef LocalFree
}  // namespace

static constexpr PCWSTR kTestPolicyPath = L"Software\\Policies\\Google\\Chrome";

static void TestRequire(bool result, const char* description) {
    if (!result) {
        throw std::runtime_error(description);
    }
}

static void TestCheck(LSTATUS result, const char* description) {
    if (result != ERROR_SUCCESS) {
        throw std::runtime_error(std::string(description) +
                                 ": Windows error " + std::to_string(result));
    }
}

struct TestKey {
    HKEY key = nullptr;
    bool hooked = false;
    TestKey() = default;
    explicit TestKey(HKEY value, bool useHook = false)
        : key(value), hooked(useHook) {}
    TestKey(const TestKey&) = delete;
    TestKey& operator=(const TestKey&) = delete;
    TestKey(TestKey&& other) noexcept
        : key(std::exchange(other.key, nullptr)), hooked(other.hooked) {}
    ~TestKey() {
        if (key) {
            if (hooked) {
                RegCloseKey_Hook(key);
            } else {
                RegCloseKey(key);
            }
        }
    }
};

struct TestHandle {
    HANDLE value = nullptr;
    TestHandle() = default;
    TestHandle(const TestHandle&) = delete;
    ~TestHandle() {
        if (value && value != INVALID_HANDLE_VALUE) CloseHandle(value);
    }
};

struct TestUserSecurity {
    std::vector<BYTE> user;
    std::wstring sid;
    PSECURITY_DESCRIPTOR descriptor = nullptr;
    SECURITY_ATTRIBUTES attributes{sizeof(SECURITY_ATTRIBUTES), nullptr, FALSE};
    TestUserSecurity() {
        TestHandle token;
        TestRequire(OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token.value) != FALSE,
                    "Open fixture identity token");
        DWORD bytes{};
        GetTokenInformation(token.value, TokenUser, nullptr, 0, &bytes);
        TestRequire(bytes != 0, "Read fixture identity size");
        user.resize(bytes);
        TestRequire(GetTokenInformation(token.value, TokenUser, user.data(), bytes, &bytes) != FALSE,
                    "Read fixture identity");
        LPWSTR text{};
        TestRequire(ConvertSidToStringSidW(
                        reinterpret_cast<TOKEN_USER*>(user.data())->User.Sid, &text) != FALSE,
                    "Format fixture user SID");
        sid = text;
        LocalFree(text);
        const auto sddl = L"O:" + sid + L"D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;" + sid + L")";
        TestRequire(ConvertStringSecurityDescriptorToSecurityDescriptorW(
                        sddl.c_str(), SDDL_REVISION_1, &descriptor, nullptr) != FALSE,
                    "Create current-user-only fixture descriptor");
        attributes.lpSecurityDescriptor = descriptor;
    }
    TestUserSecurity(const TestUserSecurity&) = delete;
    ~TestUserSecurity() { if (descriptor) LocalFree(descriptor); }
};

static std::wstring TestGuidText() {
    GUID id{};
    TestRequire(SUCCEEDED(CoCreateGuid(&id)), "Create fixture GUID");
    wchar_t result[40]{};
    TestRequire(StringFromGUID2(id, result, static_cast<int>(std::size(result))) > 0,
                "Format fixture GUID");
    return result;
}

static void TestWriteFixtureFile(const std::filesystem::path& path,
                                 SECURITY_ATTRIBUTES* attributes) {
    TestHandle file;
    file.value = CreateFileW(path.c_str(), GENERIC_WRITE, FILE_SHARE_READ,
                             attributes, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, nullptr);
    TestRequire(file.value != INVALID_HANDLE_VALUE, "Create owned cleanup fixture file");
    constexpr char data[] = "isolated-test-fixture";
    DWORD written{};
    TestRequire(WriteFile(file.value, data, sizeof(data), &written, nullptr) != FALSE &&
                    written == sizeof(data), "Write cleanup fixture marker");
}

static DWORD TestAbsentPid(DWORD start) {
    for (unsigned attempt = 0; attempt < 64; ++attempt) {
        const DWORD pid = start - attempt * 4;
        TestHandle process;
        process.value = OpenProcess(SYNCHRONIZE, FALSE, pid);
        if (!process.value && GetLastError() == ERROR_INVALID_PARAMETER) return pid;
    }
    throw std::runtime_error("Cannot select a verifiably absent PID for cleanup fixtures");
}

static TestKey TestCreate(HKEY parent, PCWSTR path) {
    HKEY key{};
    TestCheck(RegCreateKeyExW(parent, path, 0, nullptr, REG_OPTION_VOLATILE,
                              KEY_ALL_ACCESS, nullptr, &key, nullptr),
              "Create fixture key");
    return TestKey(key);
}

static TestKey TestOpen(HKEY parent, PCWSTR path, bool hooked = false,
                        REGSAM access = KEY_READ) {
    HKEY key{};
    TestCheck(hooked ? RegOpenKeyExW_Hook(parent, path, 0, access, &key)
                     : RegOpenKeyExW(parent, path, 0, access, &key),
              "Open fixture/overlay key");
    return TestKey(key, hooked);
}

static void TestSetDword(HKEY key, PCWSTR name, DWORD value) {
    TestCheck(RegSetValueExW(key, name, 0, REG_DWORD,
                            reinterpret_cast<const BYTE*>(&value), sizeof(value)),
              "Write fixture DWORD");
}

static void TestSetString(HKEY key, PCWSTR name, PCWSTR value) {
    TestCheck(RegSetValueExW(
                  key, name, 0, REG_SZ, reinterpret_cast<const BYTE*>(value),
                  static_cast<DWORD>((wcslen(value) + 1) * sizeof(wchar_t))),
              "Write fixture string");
}

static DWORD TestDword(HKEY key, PCWSTR name) {
    DWORD type{}, value{}, size = sizeof(value);
    TestCheck(RegQueryValueExW(key, name, nullptr, &type,
                              reinterpret_cast<BYTE*>(&value), &size),
              "Read DWORD");
    TestRequire(type == REG_DWORD && size == sizeof(value), "DWORD type/size");
    return value;
}

static std::wstring TestString(HKEY key, PCWSTR name) {
    DWORD type{}, size{};
    TestCheck(RegQueryValueExW(key, name, nullptr, &type, nullptr, &size),
              "Read string size");
    TestRequire(type == REG_SZ && size >= sizeof(wchar_t), "String type/size");
    std::vector<wchar_t> value(size / sizeof(wchar_t));
    TestCheck(RegQueryValueExW(key, name, nullptr, &type,
                              reinterpret_cast<BYTE*>(value.data()), &size),
              "Read string value");
    TestRequire(value.back() == L'\0', "String termination");
    return value.data();
}

static bool TestMissingValue(HKEY key, PCWSTR name) {
    DWORD size{};
    return RegQueryValueExW(key, name, nullptr, nullptr, nullptr, &size) ==
           ERROR_FILE_NOT_FOUND;
}

static std::vector<std::wstring> TestList(HKEY parent, PCWSTR name) {
    DWORD type{}, bytes{};
    auto query = RegQueryValueExW(parent, name, nullptr, &type, nullptr, &bytes);
    if (query == ERROR_SUCCESS) {
        TestRequire(type == REG_SZ, "Synthetic list is native REG_SZ JSON");
        const auto json = TestString(parent, name);
        TestRequire(json.size() >= 2 && json.front() == L'[' && json.back() == L']',
                    "JSON list brackets");
        std::vector<std::wstring> values;
        size_t offset = 1;
        while (offset + 1 < json.size()) {
            TestRequire(json[offset++] == L'"', "JSON list string start");
            const auto end = json.find(L'"', offset);
            TestRequire(end != std::wstring::npos, "JSON list string end");
            values.push_back(json.substr(offset, end - offset));
            offset = end + 1;
            if (offset + 1 < json.size()) {
                TestRequire(json[offset++] == L',', "JSON list comma");
            }
        }
        TestRequire(offset == json.size() - 1, "JSON list fully parsed");
        std::sort(values.begin(), values.end());
        return values;
    }
    TestRequire(query == ERROR_FILE_NOT_FOUND, "List value absent or readable");
    HKEY raw{};
    const auto result = RegOpenKeyExW(parent, name, 0, KEY_READ, &raw);
    if (result == ERROR_FILE_NOT_FOUND) {
        return {};
    }
    TestCheck(result, "Open list");
    TestKey list(raw);
    std::vector<std::wstring> values;
    for (DWORD index = 0;; ++index) {
        wchar_t valueName[64]{};
        DWORD length = static_cast<DWORD>(std::size(valueName));
        const auto status = RegEnumValueW(
            list.key, index, valueName, &length, nullptr, nullptr, nullptr, nullptr);
        if (status == ERROR_NO_MORE_ITEMS) {
            break;
        }
        TestCheck(status, "Enumerate list value names");
        values.push_back(TestString(list.key, valueName));
    }
    std::sort(values.begin(), values.end());
    return values;
}

static void TestOverlayValues(HKEY key, std::vector<std::wstring> keep) {
    TestRequire(TestDword(key, L"DefaultCookiesSetting") == 4, "Session-only default");
    std::vector<std::wstring> expected{
        L"autofill", L"browsing_history", L"cached_images_and_files",
        L"download_history", L"hosted_app_data", L"site_settings"};
    std::sort(expected.begin(), expected.end());
    TestRequire(TestList(key, L"ClearBrowsingDataOnExitList") == expected,
                "Exactly six exit-cleanup categories");
    for (auto& item : keep) {
        item = L"[*.]" + item;
    }
    std::sort(keep.begin(), keep.end());
    TestRequire(TestList(key, L"CookiesAllowedForUrls") == keep,
                "Exactly the requested keep sites");
}

static void TestSettings() {
    g_testKeepSites.clear();
    TestRequire(ReadKeepSites().empty(), "Empty keep list permitted");
    g_testKeepSites = {L"", L" EXAMPLE.com ", L"https://example.com:443/path",
                      L"[*.]accounts.example.org", L"https://xn--bcher-kva.de/"};
    const auto sites = ReadKeepSites();
    TestRequire(sites == std::vector<std::wstring>{
                            L"example.com", L"accounts.example.org", L"xn--bcher-kva.de"},
                "Normalization, deduplication, blank rows, punycode");
    const std::vector<std::wstring> invalid{
        L"*", L"localhost", L"a..com", L"-a.example", L"example-.com",
        L"https://user:pass@example.com/", L"https://example.com:0",
        L"https://example.com:65536", L"127.0.0.1", L"example.com/path",
        L"https://example.com:abc", L"https://[::1]/"};
    for (const auto& value : invalid) {
        bool rejected = false;
        try {
            NormalizeSite(value);
        } catch (const SettingsError&) {
            rejected = true;
        }
        TestRequire(rejected, "Malformed keep site rejected");
    }
    g_testKeepSites.assign(257, L"example.com");
    bool oversizedRejected = false;
    try {
        ReadKeepSites();
    } catch (const SettingsError&) {
        oversizedRejected = true;
    }
    TestRequire(oversizedRejected, "257th keep row rejected");
    g_testKeepSites.assign(256, L"example.com");
    TestRequire(ReadKeepSites() == std::vector<std::wstring>{L"example.com"},
                "256 rows permitted and deduplicated");
    std::puts("PASS keep-site normalization, blank/default list, validation and limits");
}

static void TestStaleCleanup() {
    TestRequire(SetOverlaySites(nullptr), "Disable before stale-storage fixtures");
    const auto normalStorage = g_testStorage;
    TestUserSecurity security;
    const std::filesystem::path base = std::filesystem::path(normalStorage) / L"cleanup-fixtures";
    TestRequire(CreateDirectoryW(base.c_str(), &security.attributes) != FALSE,
                "Create isolated cleanup fixture directory");
    const auto prefix = L"overlay-" + security.sid + L"-";
    const DWORD deadPid = TestAbsentPid(MAXDWORD - 3);
    const DWORD unknownPid = TestAbsentPid(deadPid - 4);
    auto nameFor = [&](DWORD pid) {
        return prefix + std::to_wstring(pid) + L"-" + TestGuidText();
    };
    auto directory = [&](const std::wstring& name) {
        const auto path = base / name;
        TestRequire(CreateDirectoryW(path.c_str(), &security.attributes) != FALSE,
                    "Create owned cleanup fixture directory");
        return path;
    };
    const auto stale = directory(nameFor(deadPid));
    TestWriteFixtureFile(stale / L"view.dat", &security.attributes);
    TestWriteFixtureFile(stale / L"view.dat.LOG1", &security.attributes);
    TestWriteFixtureFile(stale / L"view.dat.LOG2", &security.attributes);
    // This live creator has made a directory but has not pinned or loaded it.
    const auto liveGap = directory(nameFor(GetCurrentProcessId()));
    const auto unknown = directory(nameFor(unknownPid));
    TestWriteFixtureFile(unknown / L"view.dat", &security.attributes);
    const auto foreignName = directory(
        L"overlay-S-1-5-18-" + std::to_wstring(deadPid) + L"-" + TestGuidText());
    TestWriteFixtureFile(foreignName / L"view.dat", &security.attributes);
    const auto malformed = directory(prefix + std::to_wstring(deadPid) + L"-not-a-guid");
    TestWriteFixtureFile(malformed / L"view.dat", &security.attributes);
    const auto unknownFile = directory(nameFor(deadPid));
    TestWriteFixtureFile(unknownFile / L"view.dat", &security.attributes);
    TestWriteFixtureFile(unknownFile / L"keep-me.txt", &security.attributes);

    const auto foreignOwner = base / nameFor(deadPid);
    PSECURITY_DESCRIPTOR foreignDescriptor{};
    const auto foreignSddl = L"O:BAD:P(A;OICI;FA;;;" + security.sid + L")";
    TestRequire(ConvertStringSecurityDescriptorToSecurityDescriptorW(
                    foreignSddl.c_str(), SDDL_REVISION_1, &foreignDescriptor, nullptr) != FALSE,
                "Build foreign-owner fixture descriptor");
    SECURITY_ATTRIBUTES foreignAttributes{sizeof(SECURITY_ATTRIBUTES), foreignDescriptor, FALSE};
    const bool hasForeignOwner = CreateDirectoryW(foreignOwner.c_str(), &foreignAttributes) != FALSE;
    const DWORD foreignError = GetLastError();
    LocalFree(foreignDescriptor);
    if (!hasForeignOwner) {
        std::printf("SKIP foreign-owner fixture: token cannot assign the Administrators owner (%lu).\n",
                    static_cast<unsigned long>(foreignError));
    }

    const auto target = directory(L"reparse-target");
    TestWriteFixtureFile(target / L"view.dat", &security.attributes);
    const auto reparse = base / nameFor(deadPid);
    const bool hasReparse = CreateSymbolicLinkW(
        reparse.c_str(), target.c_str(), SYMBOLIC_LINK_FLAG_DIRECTORY | 0x2) != FALSE;
    if (!hasReparse) {
        std::printf("SKIP directory-link fixture: symbolic-link creation unavailable (%lu).\n",
                    static_cast<unsigned long>(GetLastError()));
    }

    g_testStorage = base.wstring();
    g_testUnknownProcessPid = unknownPid;
    const std::vector<std::wstring> keep{L"example.com"};
    const bool prepared = SetOverlaySites(&keep);
    g_testUnknownProcessPid = 0;
    TestRequire(prepared, "Prepare hive with stale-storage fixtures present");
    TestRequire(!std::filesystem::exists(stale),
                "Exact owned stale hive and its known logs are removed");
    TestRequire(std::filesystem::exists(liveGap),
                "Live creator is preserved before acquiring its directory pin");
    TestRequire(std::filesystem::exists(unknown / L"view.dat"),
                "Unverifiable creator is preserved without attempting elevation");
    TestRequire(std::filesystem::exists(foreignName / L"view.dat") &&
                    std::filesystem::exists(malformed / L"view.dat"),
                "Other-user and malformed directory names are preserved");
    TestRequire(std::filesystem::exists(unknownFile / L"view.dat") &&
                    std::filesystem::exists(unknownFile / L"keep-me.txt"),
                "Unrecognized file prevents all deletion in that directory");
    TestRequire(!hasForeignOwner || std::filesystem::exists(foreignOwner),
                "Unexpected directory owner is preserved");
    TestRequire(!hasReparse || (std::filesystem::is_symlink(reparse) &&
                                  std::filesystem::exists(target / L"view.dat")),
                "Directory reparse point and its target are preserved");
    TestRequire(SetOverlaySites(nullptr), "Release cleanup test configuration");
    g_testStorage = normalStorage;
    std::filesystem::remove_all(base);
    std::puts("PASS stale-cache cleanup removes only exact inactive owned files; live/unknown/foreign/extra-file paths remain");
}

static void TestRestrictedPreparation() {
    TestHandle original, restricted, impersonation;
    alignas(void*) BYTE adminSid[SECURITY_MAX_SID_SIZE]{};
    DWORD sidBytes = sizeof(adminSid);
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_DUPLICATE | TOKEN_QUERY, &original.value) ||
        !CreateWellKnownSid(WinBuiltinAdministratorsSid, nullptr, adminSid, &sidBytes)) {
        std::printf("SKIP restricted-token API check: token preparation unavailable (%lu).\n",
                    static_cast<unsigned long>(GetLastError()));
        return;
    }
    SID_AND_ATTRIBUTES denyAdmin{adminSid, 0};
    if (!CreateRestrictedToken(original.value, DISABLE_MAX_PRIVILEGE, 1, &denyAdmin,
                               0, nullptr, 0, nullptr, &restricted.value) ||
        !DuplicateTokenEx(restricted.value, TOKEN_QUERY | TOKEN_IMPERSONATE,
                           nullptr, SecurityImpersonation, TokenImpersonation,
                           &impersonation.value)) {
        std::printf("SKIP restricted-token API check: restricted token unavailable (%lu).\n",
                    static_cast<unsigned long>(GetLastError()));
        return;
    }
    TestUserSecurity security;
    const auto normalStorage = g_testStorage;
    const auto base = std::filesystem::path(normalStorage) / L"restricted-api-fixture";
    TestRequire(CreateDirectoryW(base.c_str(), &security.attributes) != FALSE,
                "Create current-user-owned restricted API fixture");
    if (!ImpersonateLoggedOnUser(impersonation.value)) {
        std::printf("SKIP restricted-token API check: impersonation unavailable (%lu).\n",
                    static_cast<unsigned long>(GetLastError()));
        std::filesystem::remove_all(base);
        return;
    }
    struct Revert {
        bool active = true;
        ~Revert() { if (active) RevertToSelf(); }
    } revert;
    BOOL administrator = TRUE;
    TestRequire(CheckTokenMembership(nullptr, adminSid, &administrator) != FALSE && !administrator,
                "Effective restricted token has no active Administrators membership");
    DWORD bytes{};
    GetTokenInformation(impersonation.value, TokenPrivileges, nullptr, 0, &bytes);
    TestRequire(bytes != 0, "Restricted privilege metadata size");
    std::vector<BYTE> privilegeData(bytes);
    TestRequire(GetTokenInformation(impersonation.value, TokenPrivileges,
                                    privilegeData.data(), bytes, &bytes) != FALSE,
                "Inspect restricted privileges");
    LUID traversal{};
    TestRequire(LookupPrivilegeValueW(nullptr, SE_CHANGE_NOTIFY_NAME, &traversal) != FALSE,
                "Identify traversal privilege");
    const auto* privileges = reinterpret_cast<TOKEN_PRIVILEGES*>(privilegeData.data());
    for (DWORD i = 0; i < privileges->PrivilegeCount; ++i) {
        const auto& entry = privileges->Privileges[i];
        TestRequire(!(entry.Attributes & SE_PRIVILEGE_ENABLED) ||
                        (entry.Luid.LowPart == traversal.LowPart &&
                         entry.Luid.HighPart == traversal.HighPart),
                    "No enabled privilege except ordinary directory traversal");
    }
    // This is deliberately single-threaded: newly created threads would use
    // the primary process token, not inherit this thread's impersonation.
    TestRequire(SetOverlaySites(nullptr), "Disable before restricted API fixture");
    g_testStorage = base.wstring();
    const std::vector<std::wstring> keep{L"example.com"};
    TestRequire(SetOverlaySites(&keep), "Prepare actual app hive with restricted effective token");
    {
        auto key = TestOpen(HKEY_CURRENT_USER, kTestPolicyPath, true);
        TestOverlayValues(key.key, keep);
    }
    TestRequire(SetOverlaySites(nullptr), "Close restricted app hive and storage normally");
    g_testStorage = normalStorage;
    TestRequire(RevertToSelf() != FALSE, "Finish restricted API fixture impersonation");
    revert.active = false;
    std::filesystem::remove_all(base);
    std::puts("PASS restricted-token API check: admin membership disabled; no enabled backup/restore or other elevated privileges");
    std::puts("NOTE restricted impersonation checks API access only; the CI process primary token and real Chrome were not changed.");
}

static void TestSimulateFreshOverlayDll() {
    TestRequire(!InitializeOverlayStorage(),
                "Unloaded module permanently rejects late initialization");
    TestRequire(g_overlayState == nullptr && !g_overlayEnabled && !g_overlayTrackedCount,
                "Shutdown retires all active bookkeeping");
    // Native test executable keeps the extracted globals in memory. This reset
    // models loading a different DLL; callers must first join all old work.
    g_overlayHooksRemoved.store(false);
    TestRequire(InitializeOverlayStorage(), "Simulated fresh DLL can initialize");
}

static void TestBlockedPreparation() {
    auto unrelated = TestCreate(HKEY_CURRENT_USER, L"Software\\UnrelatedCleanupTest");
    TestSetDword(unrelated.key, L"Unrelated", 17);
    const std::vector<std::wstring> oldSites{L"obsolete.example.com"};
    const std::vector<std::wstring> winningSites{L"winner.example.net"};
    for (const unsigned newerAction : {0u, 1u, 2u}) {
        TestRequire(SetOverlaySites(nullptr), "Disable before controlled slow preparation");
        ShutdownOverlay();
        TestSimulateFreshOverlayDll();
        HANDLE trafficDone = CreateEventW(nullptr, TRUE, FALSE, nullptr);
        HANDLE newerDone = CreateEventW(nullptr, TRUE, FALSE, nullptr);
        g_testSlowEntered = CreateEventW(nullptr, TRUE, FALSE, nullptr);
        g_testSlowRelease = CreateEventW(nullptr, TRUE, FALSE, nullptr);
        TestRequire(trafficDone && newerDone && g_testSlowEntered && g_testSlowRelease,
                    "Create controlled preparation events");
        g_testSlowTimeout = false;
        g_testSlowPoint = TestSlowPoint::HiveLoad;
        std::atomic<bool> oldReturned{false}, newerAccepted{false};
        std::atomic<LSTATUS> trafficStatus{ERROR_INVALID_DATA};
        std::thread oldRequest([&] {
            SetOverlaySites(&oldSites);
            oldReturned = true;
        });
        const auto entered = WaitForSingleObject(g_testSlowEntered, 3000);
        bool trafficCompletedBeforeRelease = false;
        bool newerCompletedBeforeRelease = false;
        std::thread traffic, newerRequest;
        if (entered == WAIT_OBJECT_0) {
            traffic = std::thread([&] {
                HKEY key{};
                auto result = RegOpenKeyExW_Hook(
                    HKEY_CURRENT_USER, L"Software\\UnrelatedCleanupTest", 0, KEY_READ, &key);
                if (result == ERROR_SUCCESS) result = RegCloseKey_Hook(key);
                trafficStatus = result;
                SetEvent(trafficDone);
            });
            newerRequest = std::thread([&] {
                if (newerAction == 2) {
                    ShutdownOverlay();
                    newerAccepted = !InitializeOverlayStorage();
                } else {
                    newerAccepted = SetOverlaySites(newerAction == 1 ? &winningSites : nullptr);
                }
                SetEvent(newerDone);
            });
            trafficCompletedBeforeRelease = WaitForSingleObject(trafficDone, 1500) == WAIT_OBJECT_0;
            newerCompletedBeforeRelease = WaitForSingleObject(newerDone, 1500) == WAIT_OBJECT_0;
        }
        SetEvent(g_testSlowRelease);
        oldRequest.join();
        if (traffic.joinable()) traffic.join();
        if (newerRequest.joinable()) newerRequest.join();
        g_testSlowPoint = TestSlowPoint::None;
        CloseHandle(trafficDone);
        CloseHandle(newerDone);
        CloseHandle(g_testSlowEntered);
        CloseHandle(g_testSlowRelease);
        g_testSlowEntered = g_testSlowRelease = nullptr;
        TestRequire(entered == WAIT_OBJECT_0 && !g_testSlowTimeout && oldReturned,
                    "Old enable was blocked in genuine private-hive preparation");
        TestRequire(trafficCompletedBeforeRelease && trafficStatus == ERROR_SUCCESS,
                    "Unrelated registry open/close progresses during slow preparation");
        TestRequire(newerCompletedBeforeRelease && newerAccepted,
                    "Newer setting publishes without waiting for old preparation");
        auto current = TestOpen(HKEY_CURRENT_USER, kTestPolicyPath, true);
        if (newerAction == 1) {
            TestOverlayValues(current.key, winningSites);
        } else {
            TestRequire(TestMissingValue(current.key, L"DefaultCookiesSetting"),
                        "Older enable cannot overwrite a newer disable or shutdown");
        }
        if (newerAction == 2) {
            TestRequire(!SetOverlaySites(&winningSites) && g_overlayState == nullptr,
                        "Late settings cannot resurrect unloaded overlay state");
            TestSimulateFreshOverlayDll();
        }
    }
    TestRequire(SetOverlaySites(nullptr), "Finish controlled preparation cases");
    std::puts("PASS slow preparation permits unrelated registry I/O; newer disable/settings/unload win");
}

static void TestOverlay() {
    SetOverlaySites(nullptr);
    HKEY missing{};
    TestRequire(RegOpenKeyExW_Hook(HKEY_CURRENT_USER, kTestPolicyPath, 0,
                                   KEY_READ, &missing) == ERROR_FILE_NOT_FOUND,
                "Disabled overlay preserves absent real branch");

    const std::vector<std::wstring> empty;
    SetOverlaySites(&empty);
    {
        auto key = TestOpen(HKEY_CURRENT_USER, kTestPolicyPath, true);
        TestOverlayValues(key.key, {});
    }
    TestRequire(RegOpenKeyExW(HKEY_CURRENT_USER, kTestPolicyPath, 0,
                             KEY_READ, &missing) == ERROR_FILE_NOT_FOUND,
                "Enabled overlay did not create a real policy branch");
    TestRequire(RegOpenKeyExW_Hook(HKEY_LOCAL_MACHINE, kTestPolicyPath, 0,
                                   KEY_READ, &missing) == ERROR_FILE_NOT_FOUND,
                "HKLM receives no synthetic branch");
    std::puts("PASS disabled default, explicit empty keep list, exact user scope, no real writes");

    auto genuine = TestCreate(HKEY_CURRENT_USER, kTestPolicyPath);
    TestSetDword(genuine.key, L"UnrelatedPolicy", 42);
    {
        auto recommended = TestCreate(genuine.key, L"Recommended");
        TestSetString(recommended.key, L"HomepageLocation", L"about:blank");
    }
    TestBlockedPreparation();
    const std::vector<std::wstring> keepA{L"example.com", L"accounts.example.org"};
    TestRequire(SetOverlaySites(&keepA), "Prepare keep-site generation");
    const auto preparedHiveLoads = g_testHiveLoads.load();
    for (unsigned read = 0; read < 3; ++read) {
        auto reused = TestOpen(HKEY_CURRENT_USER, kTestPolicyPath, true);
        TestOverlayValues(reused.key, keepA);
    }
    TestRequire(g_testHiveLoads == preparedHiveLoads,
                "Repeated registry reads reuse the prepared application hive");
    std::puts("PASS repeated policy reads reuse one prepared application hive");
    {
        auto view = TestOpen(HKEY_CURRENT_USER,
                             L"sOFTWARE\\pOLICIES\\gOOGLE\\cHROME", true);
        TestOverlayValues(view.key, keepA);
        TestRequire(TestDword(view.key, L"UnrelatedPolicy") == 42,
                    "Unrelated policy copied");
        auto recommended = TestOpen(view.key, L"Recommended");
        TestRequire(TestString(recommended.key, L"HomepageLocation") == L"about:blank",
                    "Recommended subtree copied");
        DWORD type{}, bytes{};
        TestCheck(RegQueryValueExW(view.key, L"DefaultCookiesSetting", nullptr,
                                  &type, nullptr, &bytes), "Native size-only read");
        TestRequire(type == REG_DWORD && bytes == sizeof(DWORD), "Native wire size");
        BYTE shortValue{};
        bytes = sizeof(shortValue);
        TestRequire(RegQueryValueExW(view.key, L"DefaultCookiesSetting", nullptr,
                                     &type, &shortValue, &bytes) == ERROR_MORE_DATA &&
                        bytes == sizeof(DWORD), "Native short-buffer semantics");
        const DWORD attemptedWrite = 7;
        TestRequire(RegSetValueExW(view.key, L"UnexpectedWrite", 0, REG_DWORD,
                                   reinterpret_cast<const BYTE*>(&attemptedWrite),
                                   sizeof(attemptedWrite)) == ERROR_ACCESS_DENIED,
                    "Returned KEY_READ handle cannot write private policies");
    }
    TestRequire(TestMissingValue(genuine.key, L"DefaultCookiesSetting") &&
                    TestList(genuine.key, L"ClearBrowsingDataOnExitList").empty() &&
                    TestList(genuine.key, L"CookiesAllowedForUrls").empty(),
                "Original policies remain unchanged");
    std::puts("PASS unrelated policy/subtree preservation, case-insensitive path, native Win32 reads");

    {
        auto before = TestOpen(HKEY_CURRENT_USER, kTestPolicyPath, true);
        TestSetDword(genuine.key, L"UnrelatedPolicy", 43);
        auto after = TestOpen(HKEY_CURRENT_USER, kTestPolicyPath, true);
        TestRequire(TestDword(before.key, L"UnrelatedPolicy") == 42 &&
                        TestDword(after.key, L"UnrelatedPolicy") == 43,
                    "Each root read clones current genuine values without mutating older readers");
        TestSetDword(genuine.key, L"UnrelatedPolicy", 42);
    }
    std::puts("PASS reused hive still takes fresh genuine-policy snapshots on every root read");

    {
        auto before = TestOpen(HKEY_CURRENT_USER, kTestPolicyPath, true);
        const std::vector<std::wstring> keepB{L"new.example.net"};
        SetOverlaySites(&keepB);
        auto after = TestOpen(HKEY_CURRENT_USER, kTestPolicyPath, true);
        TestOverlayValues(before.key, keepA);
        TestOverlayValues(after.key, keepB);
        SetOverlaySites(nullptr);
        auto disabled = TestOpen(HKEY_CURRENT_USER, kTestPolicyPath, true);
        TestRequire(TestMissingValue(disabled.key, L"DefaultCookiesSetting"),
                    "Disable returns genuine policies for new readers");
        TestOverlayValues(before.key, keepA);
        TestOverlayValues(after.key, keepB);
    }
    std::puts("PASS settings generations and old-reader lifetime across disable");

    SetOverlaySites(&keepA);
    {
        auto parent = TestOpen(HKEY_CURRENT_USER, kTestPolicyPath, true);
        auto child = TestOpen(parent.key, L"Recommended", true);
        TestCheck(RegCloseKey_Hook(parent.key), "Close root with open relative child");
        parent.key = nullptr;
        TestRequire(TestString(child.key, L"HomepageLocation") == L"about:blank",
                    "Relative child retains snapshot after root close");
    }
    std::puts("PASS relative native child lifetime after root close");

    {
        auto parent = TestOpen(HKEY_CURRENT_USER, kTestPolicyPath, true);
        g_testSlowEntered = CreateEventW(nullptr, TRUE, FALSE, nullptr);
        g_testSlowRelease = CreateEventW(nullptr, TRUE, FALSE, nullptr);
        HANDLE childDone = CreateEventW(nullptr, TRUE, FALSE, nullptr);
        TestRequire(g_testSlowEntered && g_testSlowRelease && childDone,
                    "Create controlled native-close events");
        g_testSlowTimeout = false;
        g_testSlowPoint = TestSlowPoint::NativeClose;
        std::atomic<LSTATUS> closeStatus{ERROR_INVALID_DATA}, childStatus{ERROR_INVALID_DATA};
        HKEY child{};
        std::thread closing([&] { closeStatus = RegCloseKey_Hook(parent.key); });
        const auto closeEntered = WaitForSingleObject(g_testSlowEntered, 3000);
        bool childBeforeClose = false;
        std::thread opening;
        if (closeEntered == WAIT_OBJECT_0) {
            opening = std::thread([&] {
                childStatus = RegOpenKeyExW_Hook(parent.key, L"Recommended", 0, KEY_READ, &child);
                SetEvent(childDone);
            });
            childBeforeClose = WaitForSingleObject(childDone, 1500) == WAIT_OBJECT_0;
        }
        SetEvent(g_testSlowRelease);
        closing.join();
        if (opening.joinable()) opening.join();
        if (closeStatus == ERROR_SUCCESS) parent.key = nullptr;
        g_testSlowPoint = TestSlowPoint::None;
        CloseHandle(childDone);
        CloseHandle(g_testSlowEntered);
        CloseHandle(g_testSlowRelease);
        g_testSlowEntered = g_testSlowRelease = nullptr;
        TestKey childOwner(child, true);
        TestRequire(closeEntered == WAIT_OBJECT_0 && !g_testSlowTimeout,
                    "Close was paused before calling the native registry API");
        TestRequire(childBeforeClose && childStatus == ERROR_SUCCESS && closeStatus == ERROR_SUCCESS,
                    "Relative child can open from the still-valid parent during slow native close");
        TestRequire(g_overlayState->clients.contains(child) &&
                        TestString(child, L"HomepageLocation") == L"about:blank",
                    "Concurrent child retains the snapshot after parent close completes");
    }
    std::puts("PASS relative-open ownership is retained while the parent's native close is pending");

    {
        auto parent = TestOpen(HKEY_CURRENT_USER, kTestPolicyPath, true);
        auto child = TestOpen(parent.key, L"Recommended", true);
        const auto clients = g_overlayTrackedCount.load();
        const auto failures = g_testFailedCloses.load();
        g_testFailCloseOnce = parent.key;
        TestRequire(RegCloseKey_Hook(parent.key) == ERROR_ACCESS_DENIED &&
                        g_testFailedCloses == failures + 1,
                    "Original native close failure is returned");
        TestRequire(g_overlayTrackedCount == clients &&
                        g_overlayState->clients.contains(parent.key),
                    "Failed close retains the original tracking entry");
        TestOverlayValues(parent.key, keepA);
        TestCheck(RegCloseKey_Hook(parent.key), "Retry native close after one failure");
        parent.key = nullptr;
        TestRequire(TestString(child.key, L"HomepageLocation") == L"about:blank",
                    "Child survives parent close failure and successful retry");
    }
    std::puts("PASS failed native close retains ownership and a later close succeeds");

    {
        auto parent = TestOpen(HKEY_CURRENT_USER, kTestPolicyPath, true);
        const auto clientCount = g_overlayState->clients.size();
        Wh_Log(L"Testing tracked child allocation failure.");
        DWORD nativeHandlesBefore{}, nativeHandlesAfter{};
        TestRequire(GetProcessHandleCount(GetCurrentProcess(), &nativeHandlesBefore) != FALSE,
                    "Count handles before bookkeeping failure");
        const HKEY sentinel = reinterpret_cast<HKEY>(static_cast<uintptr_t>(0x12345));
        HKEY child = sentinel;
        g_testFailNextAllocation = true;
        const auto result = RegOpenKeyExW_Hook(parent.key, L"Recommended", 0,
                                               KEY_READ, &child);
        const bool faultWasConsumed = !g_testFailNextAllocation.exchange(false);
        TestRequire(GetProcessHandleCount(GetCurrentProcess(), &nativeHandlesAfter) != FALSE,
                    "Count handles after bookkeeping failure");
        TestRequire(faultWasConsumed && result == ERROR_NOT_ENOUGH_MEMORY,
                    "Tracked child allocation failure propagated safely");
        TestRequire(child == sentinel, "Failed tracked child handle never published");
        TestRequire(g_overlayState->clients.size() == clientCount,
                    "Tracked child failure leaves client table unchanged");
        TestRequire(nativeHandlesAfter == nativeHandlesBefore,
                    "Temporary native child handle closed after bookkeeping failure");
        TestOverlayValues(parent.key, keepA);
        auto retry = TestOpen(parent.key, L"Recommended", true);
        TestRequire(TestString(retry.key, L"HomepageLocation") == L"about:blank",
                    "Relative child succeeds after allocation failure");
    }
    std::puts("PASS relative-open allocation failure closes native child and preserves parent");

    SetOverlaySites(&keepA);
    TestSetDword(genuine.key, L"DefaultCookiesSetting", 2);
    {
        auto conflicted = TestOpen(HKEY_CURRENT_USER, kTestPolicyPath, true);
        TestRequire(TestDword(conflicted.key, L"DefaultCookiesSetting") == 2,
                    "Existing user policy not replaced");
        TestRequire(TestList(conflicted.key, L"ClearBrowsingDataOnExitList").empty(),
                    "User conflict blocks entire overlay");
    }
    TestCheck(RegDeleteValueW(genuine.key, L"DefaultCookiesSetting"), "Remove fixture conflict");
    {
        auto machine = TestCreate(HKEY_LOCAL_MACHINE, kTestPolicyPath);
        TestSetDword(machine.key, L"DefaultCookiesSetting", 2);
        auto conflicted = TestOpen(HKEY_CURRENT_USER, kTestPolicyPath, true);
        TestRequire(TestMissingValue(conflicted.key, L"DefaultCookiesSetting"),
                    "Machine conflict blocks entire overlay");
        TestRequire(TestDword(machine.key, L"DefaultCookiesSetting") == 2,
                    "Machine policy never changed");
        TestCheck(RegDeleteValueW(machine.key, L"DefaultCookiesSetting"),
                  "Remove machine fixture conflict");
    }
    {
        auto keepConflict = TestCreate(genuine.key, L"CookiesAllowedForUrls");
        TestSetString(keepConflict.key, L"1", L"[*.]existing.example");
        auto conflicted = TestOpen(HKEY_CURRENT_USER, kTestPolicyPath, true);
        TestRequire(TestMissingValue(conflicted.key, L"DefaultCookiesSetting"),
                    "Existing allow list blocks entire overlay");
        TestRequire(TestList(conflicted.key, L"CookiesAllowedForUrls") ==
                        std::vector<std::wstring>{L"[*.]existing.example"},
                    "Existing allow list preserved exactly");
    }
    TestCheck(RegDeleteTreeW(genuine.key, L"CookiesAllowedForUrls"), "Remove allow-list fixture");
    {
        auto restored = TestOpen(HKEY_CURRENT_USER, kTestPolicyPath, true);
        TestOverlayValues(restored.key, keepA);
    }
    std::puts("PASS user/machine/list conflicts and recovery when original conflicts disappear");

    {
        struct RetryCase {
            LSTATUS code;
            unsigned availableFailures;
            unsigned expectedFailures;
            bool expectOverlay;
        };
        for (const auto& item : {
                 RetryCase{ERROR_RETRY, 1, 1, true},
                 RetryCase{ERROR_MORE_DATA, 1, 1, true},
                 RetryCase{ERROR_RETRY, 5, 2, false},
                 RetryCase{ERROR_MORE_DATA, 5, 2, false},
                 RetryCase{ERROR_ACCESS_DENIED, 5, 1, false}}) {
            g_testEnumFaultCode = item.code;
            g_testEnumFaultsInjected = 0;
            g_testEnumFaultsRemaining = item.availableFailures;
            auto key = TestOpen(HKEY_CURRENT_USER, kTestPolicyPath, true);
            const auto injected = g_testEnumFaultsInjected.load();
            g_testEnumFaultsRemaining = 0;
            TestRequire(injected == item.expectedFailures,
                        "Only changed-tree failures retry, with exactly two attempts maximum");
            if (item.expectOverlay) {
                TestOverlayValues(key.key, keepA);
            } else {
                TestRequire(TestMissingValue(key.key, L"DefaultCookiesSetting") &&
                                TestDword(key.key, L"UnrelatedPolicy") == 42,
                            "Failed snapshot returns genuine policies without partial overlay");
            }
        }
    }
    std::puts("PASS changed-tree retry recovery, two-attempt bound and non-retryable failure fallback");

    {
        // Exceed 4 MiB in aggregate, using small native registry cells. A
        // single multi-megabyte value isn't supported by some volatile hives.
        std::vector<BYTE> oversized(4096, 0x2a);
        for (unsigned index = 0; index < 1024; ++index) {
            const auto name = L"LargeUnrelatedPolicy" + std::to_wstring(index);
            TestCheck(RegSetValueExW(genuine.key, name.c_str(), 0, REG_BINARY,
                                    oversized.data(), static_cast<DWORD>(oversized.size())),
                      "Write aggregate-size fixture value");
        }
        auto fallback = TestOpen(HKEY_CURRENT_USER, kTestPolicyPath, true);
        TestRequire(TestMissingValue(fallback.key, L"DefaultCookiesSetting"),
                    "Copy limit causes genuine-policy fallback");
        DWORD bytes{};
        TestCheck(RegQueryValueExW(fallback.key, L"LargeUnrelatedPolicy1023", nullptr,
                                  nullptr, nullptr, &bytes), "Oversized genuine value visible");
        TestRequire(bytes == oversized.size(), "Oversized genuine value not truncated");
        for (unsigned index = 0; index < 1024; ++index) {
            const auto name = L"LargeUnrelatedPolicy" + std::to_wstring(index);
            TestCheck(RegDeleteValueW(genuine.key, name.c_str()), "Remove aggregate-size fixture");
        }
    }
    std::puts("PASS bounded clone failure preserves original values with no synthetic policy");

    {
        SetOverlaySites(nullptr);
        ShutdownOverlay();
        const auto goodStorage = g_testStorage;
        g_testStorage += L"\\missing-parent\\unavailable";
        TestSimulateFreshOverlayDll();
        TestRequire(!SetOverlaySites(&keepA), "Failed hive preparation rejects enabled settings");
        {
            auto fallback = TestOpen(HKEY_CURRENT_USER, kTestPolicyPath, true);
            TestRequire(TestMissingValue(fallback.key, L"DefaultCookiesSetting"),
                        "Unavailable storage falls back to genuine policies");
            TestRequire(TestDword(fallback.key, L"UnrelatedPolicy") == 42,
                        "Unavailable storage preserves unrelated policy");
        }
        SetOverlaySites(nullptr);
        ShutdownOverlay();
        g_testStorage = goodStorage;
        TestSimulateFreshOverlayDll();
        TestRequire(SetOverlaySites(&keepA), "Restore enabled configuration");
        auto recovered = TestOpen(HKEY_CURRENT_USER, kTestPolicyPath, true);
        TestOverlayValues(recovered.key, keepA);
    }
    std::puts("PASS unavailable storage fails safely and a later module restart recovers");

    {
        std::atomic<unsigned> failures{0};
        auto reader = [&] {
            for (int i = 0; i < 12; ++i) {
                try {
                    auto key = TestOpen(HKEY_CURRENT_USER, kTestPolicyPath, true);
                    const auto list = TestList(key.key, L"CookiesAllowedForUrls");
                    TestRequire(list == std::vector<std::wstring>{
                                            L"[*.]accounts.example.org", L"[*.]example.com"} ||
                                    list == std::vector<std::wstring>{L"[*.]new.example.net"},
                                "Reader sees one whole generation");
                    TestRequire(TestDword(key.key, L"DefaultCookiesSetting") == 4,
                                "Concurrent complete overlay");
                } catch (...) {
                    ++failures;
                }
            }
        };
        std::thread first(reader), second(reader);
        const std::vector<std::wstring> keepB{L"new.example.net"};
        for (int i = 0; i < 12; ++i) {
            SetOverlaySites(i % 2 ? &keepA : &keepB);
        }
        first.join();
        second.join();
        TestRequire(failures == 0, "Concurrent reader/update transactions");
    }
    std::puts("PASS concurrent real-handle readers and settings updates");

    SetOverlaySites(&keepA);
    auto survivor = TestOpen(HKEY_CURRENT_USER, kTestPolicyPath, true);
    g_testSlowEntered = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    g_testSlowRelease = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    HANDLE shutdownDone = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    TestRequire(g_testSlowEntered && g_testSlowRelease && shutdownDone,
                "Create controlled snapshot/unload events");
    g_testSlowTimeout = false;
    g_testSlowPoint = TestSlowPoint::EnumerateValue;
    HKEY lateReader{};
    std::atomic<LSTATUS> lateStatus{ERROR_INVALID_DATA};
    std::thread inFlight([&] {
        lateStatus = RegOpenKeyExW_Hook(HKEY_CURRENT_USER, kTestPolicyPath, 0,
                                      KEY_READ, &lateReader);
    });
    const auto snapshotEntered = WaitForSingleObject(g_testSlowEntered, 3000);
    bool stoppedBeforeRelease = false;
    std::thread unload;
    if (snapshotEntered == WAIT_OBJECT_0) {
        unload = std::thread([&] {
            ShutdownOverlay();
            SetEvent(shutdownDone);
        });
        stoppedBeforeRelease = WaitForSingleObject(shutdownDone, 1500) == WAIT_OBJECT_0;
    }
    SetEvent(g_testSlowRelease);
    inFlight.join();
    if (unload.joinable()) unload.join();
    g_testSlowPoint = TestSlowPoint::None;
    CloseHandle(shutdownDone);
    CloseHandle(g_testSlowEntered);
    CloseHandle(g_testSlowRelease);
    g_testSlowEntered = g_testSlowRelease = nullptr;
    TestRequire(snapshotEntered == WAIT_OBJECT_0 && !g_testSlowTimeout,
                "Reader was blocked while cloning genuine policy data");
    TestRequire(stoppedBeforeRelease, "Unload completes while native snapshot I/O is pending");
    TestCheck(lateStatus, "In-flight reader falls back safely after unload");
    TestRequire(TestMissingValue(lateReader, L"DefaultCookiesSetting") &&
                    TestDword(lateReader, L"UnrelatedPolicy") == 42,
                "In-flight snapshot cannot publish a private reader after shutdown");
    TestCheck(RegCloseKey_Hook(lateReader), "Close reader completed after unload");
    TestRequire(!InitializeOverlayStorage() && !SetOverlaySites(&keepA) &&
                    g_overlayState == nullptr && !g_overlayTrackedCount,
                "In-flight completion cannot resurrect stopped overlay state");
    TestOverlayValues(survivor.key, keepA);
    {
        auto afterUnload = TestOpen(HKEY_CURRENT_USER, kTestPolicyPath, true);
        TestRequire(TestMissingValue(afterUnload.key, L"DefaultCookiesSetting"),
                    "No synthetic policy after shutdown");
    }
    // After hook removal Chrome closes this with the real Windows API.
    TestCheck(RegCloseKey(survivor.key), "Native close after module shutdown");
    survivor.key = nullptr;
    TestRequire(TestMissingValue(genuine.key, L"DefaultCookiesSetting"),
                "No genuine policy survives module shutdown");
    std::puts("PASS shutdown during snapshot I/O, permanent stopped state and outstanding native-handle safety");
}

static bool g_testGpRegisterSuccess = true;
static unsigned g_testGpRegisters = 0, g_testGpUnregisters = 0;
static bool g_testGpReenter = false;
static BOOL WINAPI TestRegisterGp(HANDLE, BOOL) {
    TestObserveIo("RegisterGPNotification");
    ++g_testGpRegisters;
    if (g_testGpReenter) RequestPolicyRefresh(false);
    SetLastError(123);
    return g_testGpRegisterSuccess ? TRUE : FALSE;
}
static BOOL WINAPI TestUnregisterGp(HANDLE) {
    TestObserveIo("UnregisterGPNotification");
    ++g_testGpUnregisters;
    if (g_testGpReenter) RequestPolicyRefresh(false);
    SetLastError(124);
    return TRUE;
}

static void TestRefresh() {
    RegisterGPNotification_Original = TestRegisterGp;
    UnregisterGPNotification_Original = TestUnregisterGp;
    const auto logsBefore = g_testLogCount.load();
    RequestPolicyRefresh(false);
    TestRequire(g_testLogCount == logsBefore, "Ordinary startup without an event stays quiet");
    RequestPolicyRefresh();
    TestRequire(g_testLogCount == logsBefore + 1,
                "Explicit refresh without an event reports manual reload guidance");
    HANDLE event = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    TestRequire(event != nullptr, "Create native policy event");
    TestRequire(RegisterGPNotification_Hook(event, FALSE) != FALSE &&
                    GetLastError() == 123, "Registration forwards and preserves last error");
    TestRequire(RegisterGPNotification_Hook(event, TRUE) != FALSE, "Repeated registration");
    SetLastError(321);
    RequestPolicyRefresh();
    TestRequire(GetLastError() == 321 &&
                    WaitForSingleObject(event, 0) == WAIT_OBJECT_0,
                "Duplicate event wakes original and preserves last error");
    ResetEvent(event);
    TestRequire(UnregisterGPNotification_Hook(event) != FALSE &&
                    GetLastError() == 124, "Unregister forwards and preserves last error");
    RequestPolicyRefresh();
    TestRequire(WaitForSingleObject(event, 0) == WAIT_TIMEOUT,
                "One successful unregister removes the event registration");
    ResetEvent(event);
    TestRequire(UnregisterGPNotification_Hook(event) != FALSE, "Final unregister");
    RequestPolicyRefresh();
    TestRequire(WaitForSingleObject(event, 0) == WAIT_TIMEOUT,
                "No refresh after final unregister");
    g_testGpRegisterSuccess = false;
    TestRequire(RegisterGPNotification_Hook(event, FALSE) == FALSE,
                "Failed original registration propagated");
    RequestPolicyRefresh();
    TestRequire(WaitForSingleObject(event, 0) == WAIT_TIMEOUT,
                "Failed registration not retained");
    TestRequire(g_testGpRegisters == 3 && g_testGpUnregisters == 2,
                "Original APIs called exactly once per request");
    g_testGpRegisterSuccess = true;
    g_testGpReenter = true;
    TestRequire(RegisterGPNotification_Hook(event, FALSE) != FALSE &&
                    GetLastError() == 123, "Register original can reenter refresh");
    TestRequire(UnregisterGPNotification_Hook(event) != FALSE &&
                    GetLastError() == 124 && WaitForSingleObject(event, 0) == WAIT_OBJECT_0,
                "Unregister original can reenter refresh without holding its bookkeeping lock");
    g_testGpReenter = false;
    std::puts("PASS native event duplication, repeated registration, failure, reentry and last-error behavior");

    // An in-flight signal has already leased its duplicate. Unregister/unload
    // must finish before the slow signal resumes, without closing that handle.
    for (const bool unload : {false, true}) {
        ResetEvent(event);
        TestRequire(RegisterGPNotification_Hook(event, FALSE) != FALSE,
                    "Register event for concurrent retirement");
        HANDLE retireDone = CreateEventW(nullptr, TRUE, FALSE, nullptr);
        g_testSlowEntered = CreateEventW(nullptr, TRUE, FALSE, nullptr);
        g_testSlowRelease = CreateEventW(nullptr, TRUE, FALSE, nullptr);
        TestRequire(retireDone && g_testSlowEntered && g_testSlowRelease,
                    "Create controlled refresh events");
        g_testSlowTimeout = false;
        g_testSlowPoint = TestSlowPoint::SignalEvent;
        std::thread request([] { RequestPolicyRefresh(); });
        const auto entered = WaitForSingleObject(g_testSlowEntered, 3000);
        bool retiredBeforeRelease = false;
        std::atomic<bool> retireSucceeded{false};
        std::thread retire;
        if (entered == WAIT_OBJECT_0) {
            retire = std::thread([&] {
                if (unload) {
                    ClearPolicyRefreshEvents();
                    retireSucceeded = true;
                } else {
                    retireSucceeded = UnregisterGPNotification_Hook(event) != FALSE;
                }
                SetEvent(retireDone);
            });
            retiredBeforeRelease = WaitForSingleObject(retireDone, 1500) == WAIT_OBJECT_0;
        }
        SetEvent(g_testSlowRelease);
        request.join();
        if (retire.joinable()) retire.join();
        g_testSlowPoint = TestSlowPoint::None;
        CloseHandle(retireDone);
        CloseHandle(g_testSlowEntered);
        CloseHandle(g_testSlowRelease);
        g_testSlowEntered = g_testSlowRelease = nullptr;
        TestRequire(entered == WAIT_OBJECT_0 && !g_testSlowTimeout,
                    "Refresh was blocked at the native SetEvent call");
        TestRequire(retiredBeforeRelease && retireSucceeded,
                    "Unregister/unload does not wait for a blocked native signal");
        TestRequire(WaitForSingleObject(event, 0) == WAIT_OBJECT_0,
                    "Leased duplicate stays valid until its pending native signal completes");
        ResetEvent(event);
        RequestPolicyRefresh(false);
        TestRequire(WaitForSingleObject(event, 0) == WAIT_TIMEOUT,
                    "Retired registration cannot signal again");
    }
    TestRequire(RegisterGPNotification_Hook(event, FALSE) != FALSE,
                "Native registration still forwards after refresh tracking stops");
    RequestPolicyRefresh(false);
    TestRequire(WaitForSingleObject(event, 0) == WAIT_TIMEOUT,
                "A late registration cannot resurrect tracking after unload");
    CloseHandle(event);
    std::puts("PASS quiet startup, explicit empty guidance and native event leases across unregister/unload");
}

int main(int argc, char** argv) {
    if (argc >= 3 && std::string_view(argv[1]) == "--classifier-only") {
        const bool expected = std::string_view(argv[2]) == "browser";
        const bool actual = IsMainChromeProcess() != FALSE;
        std::printf("Native classifier: expected %s; got %s\n",
                    expected ? "browser" : "child", actual ? "browser" : "child");
        return expected == actual ? 0 : 1;
    }
    std::filesystem::path work;
    bool userOverridden = false, machineOverridden = false, initialized = false;
    TestKey userHive, machineHive;
    try {
        HANDLE token{};
        TestRequire(OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token) != FALSE,
                    "Open test token");
        TOKEN_ELEVATION elevation{};
        DWORD returned{};
        TestRequire(GetTokenInformation(token, TokenElevation, &elevation,
                                        sizeof(elevation), &returned) != FALSE,
                    "Read test-token elevation");
        CloseHandle(token);
        std::printf("Runner token elevated: %s\n", elevation.TokenIsElevated ? "yes" : "no");

        wchar_t temp[32768]{};
        const DWORD tempLength = GetTempPathW(static_cast<DWORD>(std::size(temp)), temp);
        TestRequire(tempLength != 0 && tempLength < std::size(temp), "Temporary directory");
        GUID id{};
        TestRequire(SUCCEEDED(CoCreateGuid(&id)), "Create unique fixture ID");
        wchar_t idText[40]{};
        TestRequire(StringFromGUID2(id, idText, static_cast<int>(std::size(idText))) > 0,
                    "Format fixture ID");
        work = std::filesystem::path(temp) / (L"WhChromeCleanupTest-" + std::wstring(idText));
        std::filesystem::create_directories(work / L"storage");
        g_testStorage = (work / L"storage").wstring();
        TestCheck(RegLoadAppKeyW((work / L"user.hiv").c_str(), &userHive.key,
                                KEY_ALL_ACCESS, REG_PROCESS_APPKEY, 0),
                  "Create isolated user hive");
        TestCheck(RegLoadAppKeyW((work / L"machine.hiv").c_str(), &machineHive.key,
                                KEY_ALL_ACCESS, REG_PROCESS_APPKEY, 0),
                  "Create isolated machine hive");
        TestCheck(RegOverridePredefKey(HKEY_CURRENT_USER, userHive.key),
                  "Isolate process HKCU");
        userOverridden = true;
        TestCheck(RegOverridePredefKey(HKEY_LOCAL_MACHINE, machineHive.key),
                  "Isolate process HKLM");
        machineOverridden = true;
        RegOpenKeyExW_Original = TestObservedRegOpen;
        RegCloseKey_Original = TestObservedRegClose;
        TestRequire(InitializeOverlayStorage(), "Initialize exact overlay module");
        initialized = true;
        TestSettings();
        TestStaleCleanup();
        TestRestrictedPreparation();
        TestOverlay();
        initialized = false;
        TestRefresh();
        if (g_testIoUnderLock || g_testAllocationUnderLock || g_testDeallocationUnderLock) {
            std::fprintf(stderr, "Locked native calls: %u; first: %s; locked allocations: %u; frees: %u\n",
                         g_testIoUnderLock.load(),
                         g_testFirstLockedIo.load() ? g_testFirstLockedIo.load() : "none",
                         g_testAllocationUnderLock.load(), g_testDeallocationUnderLock.load());
        }
        TestRequire(g_testIoUnderLock == 0 && g_testAllocationUnderLock == 0 &&
                        g_testDeallocationUnderLock == 0,
                    "No native/file/logging/storage or heap operations under bookkeeping locks");
        std::puts("PASS all observed native/file/logging/storage and heap operations execute outside bookkeeping locks");
        TestCheck(RegOverridePredefKey(HKEY_LOCAL_MACHINE, nullptr), "Restore process HKLM");
        machineOverridden = false;
        TestCheck(RegOverridePredefKey(HKEY_CURRENT_USER, nullptr), "Restore process HKCU");
        userOverridden = false;
        TestCheck(RegCloseKey(userHive.key), "Close fixture user hive"); userHive.key = nullptr;
        TestCheck(RegCloseKey(machineHive.key), "Close fixture machine hive"); machineHive.key = nullptr;
        std::error_code ignored;
        std::filesystem::remove_all(work, ignored);
        std::puts("All exact-module native Windows behavior tests passed.");
        return 0;
    } catch (const std::exception& error) {
        std::fprintf(stderr, "FAIL: %s\n", error.what());
    } catch (...) {
        std::fprintf(stderr, "FAIL: unexpected non-standard exception\n");
    }
    if (initialized) {
        SetOverlaySites(nullptr);
        ShutdownOverlay();
    }
    if (machineOverridden) RegOverridePredefKey(HKEY_LOCAL_MACHINE, nullptr);
    if (userOverridden) RegOverridePredefKey(HKEY_CURRENT_USER, nullptr);
    return 1;
}
