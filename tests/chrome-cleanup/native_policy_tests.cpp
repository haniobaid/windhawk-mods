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
#include <cstring>
#include <cwchar>
#include <cwctype>
#include <exception>
#include <filesystem>
#include <map>
#include <memory>
#include <mutex>
#include <set>
#include <stdexcept>
#include <string>
#include <string_view>
#include <thread>
#include <unordered_map>
#include <utility>
#include <vector>

std::wstring g_testStorage;
std::vector<std::wstring> g_testKeepSites;

void Wh_Log(PCWSTR format, ...) {
    wchar_t buffer[2048]{};
    va_list args;
    va_start(args, format);
    vswprintf(buffer, std::size(buffer), format, args);
    va_end(args);
    fputws(L"MOD: ", stderr);
    fputws(buffer, stderr);
    fputws(L"\n", stderr);
}

size_t Wh_GetModStoragePath(PWSTR output, size_t capacity) {
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
#include "policy_overlay.inc"
#include "mod_settings.inc"
#include "policy_refresh.inc"
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
    const std::vector<std::wstring> keepA{L"example.com", L"accounts.example.org"};
    SetOverlaySites(&keepA);
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
    }
    TestRequire(TestMissingValue(genuine.key, L"DefaultCookiesSetting") &&
                    TestList(genuine.key, L"ClearBrowsingDataOnExitList").empty() &&
                    TestList(genuine.key, L"CookiesAllowedForUrls").empty(),
                "Original policies remain unchanged");
    std::puts("PASS unrelated policy/subtree preservation, case-insensitive path, native Win32 reads");

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
        // More than the documented 4 MiB snapshot budget: fail safely to the
        // genuine registry view rather than hiding policies or truncating them.
        std::vector<BYTE> oversized(4 * 1024 * 1024 + 1, 0x2a);
        TestCheck(RegSetValueExW(genuine.key, L"LargeUnrelatedPolicy", 0, REG_BINARY,
                                oversized.data(), static_cast<DWORD>(oversized.size())),
                  "Write oversized fixture value");
        auto fallback = TestOpen(HKEY_CURRENT_USER, kTestPolicyPath, true);
        TestRequire(TestMissingValue(fallback.key, L"DefaultCookiesSetting"),
                    "Copy limit causes genuine-policy fallback");
        DWORD bytes{};
        TestCheck(RegQueryValueExW(fallback.key, L"LargeUnrelatedPolicy", nullptr,
                                  nullptr, nullptr, &bytes), "Oversized genuine value visible");
        TestRequire(bytes == oversized.size(), "Oversized genuine value not truncated");
        TestCheck(RegDeleteValueW(genuine.key, L"LargeUnrelatedPolicy"), "Remove oversized fixture");
    }
    std::puts("PASS bounded clone failure preserves original values with no synthetic policy");

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
    SetOverlaySites(nullptr);
    ShutdownOverlay();
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
    std::puts("PASS native outstanding-handle safety after shutdown and no persistent policies");
}

static bool g_testGpRegisterSuccess = true;
static unsigned g_testGpRegisters = 0, g_testGpUnregisters = 0;
static BOOL WINAPI TestRegisterGp(HANDLE, BOOL) {
    ++g_testGpRegisters;
    SetLastError(123);
    return g_testGpRegisterSuccess ? TRUE : FALSE;
}
static BOOL WINAPI TestUnregisterGp(HANDLE) {
    ++g_testGpUnregisters;
    SetLastError(124);
    return TRUE;
}

static void TestRefresh() {
    RegisterGPNotification_Original = TestRegisterGp;
    UnregisterGPNotification_Original = TestUnregisterGp;
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
    TestRequire(WaitForSingleObject(event, 0) == WAIT_OBJECT_0,
                "One registration remains after first unregister");
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
    ClearPolicyRefreshEvents();
    CloseHandle(event);
    TestRequire(g_testGpRegisters == 3 && g_testGpUnregisters == 2,
                "Original APIs called exactly once per request");
    std::puts("PASS native event duplication, repeated registration, failure, cleanup and last-error behavior");
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
        RegOpenKeyExW_Original = RegOpenKeyExW;
        RegCloseKey_Original = RegCloseKey;
        TestRequire(InitializeOverlayStorage(), "Initialize exact overlay module");
        initialized = true;
        TestSettings();
        TestOverlay();
        initialized = false;
        TestRefresh();
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
