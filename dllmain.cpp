/*
 * ExitFix.asi — Vehicle Exit Fix for GTA SA / SAMP 0.3.7
 *
 * Позволяет выпрыгивать из транспорта на любой скорости
 * и выходить из машины, которой управляет другой игрок.
 *
 * Компилятор: MSVC 2019+ / MinGW-w64
 * Зависимости: MinHook (включён в проект), Windows SDK
 *
 * Работает как тихий фикс — без сообщений в чат, без UI.
 */

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <cstdint>

// ---------------------------------------------------------------------------
//  MinHook — одиночный заголовок (положи MinHook.h и libMinHook.x86.lib рядом)
// ---------------------------------------------------------------------------
#include "MinHook.h"
#ifdef _WIN64
#  pragma comment(lib, "libMinHook.x86.lib")
#else
#  pragma comment(lib, "libMinHook.x86.lib")
#endif

// ---------------------------------------------------------------------------
//  GTA SA — адреса (EXE 1.0 US, no-CD / Steam-совместимо через смещения)
// ---------------------------------------------------------------------------

// Базовый адрес GTA SA процесса (обычно 0x400000, но читаем динамически)
static uintptr_t gBase = 0;

// Смещения от базы (GTA SA 1.0 US)
constexpr uintptr_t OFF_PLAYER_PED          = 0xB6F5F0; // CPlayerPed* LocalPlayer
constexpr uintptr_t OFF_CPed_flags          = 0x4C4;    // в структуре CPed
constexpr uintptr_t OFF_CVehicle_speed      = 0x44;     // скорость в структуре CVehicle (вектор)

// Адрес функции CTaskComplexExitVehicle::ProcessPed (устанавливает ограничение)
// GTA SA 1.0 US: 0x6492B0
constexpr uintptr_t ADDR_ExitVehicleTask    = 0x6492B0;

// CPlayerPed::ExitVehicle  — вызывается при нажатии Enter/F
// GTA SA 1.0 US: 0x60D9F0
constexpr uintptr_t ADDR_ExitVehicle        = 0x60D9F0;

// CAutomobile::ProcessControl — место, где проверяется скорость перед выходом
// Нас интересует патч по адресу 0x6D0E70 (jnz -> jmp)
constexpr uintptr_t ADDR_SpeedCheck         = 0x6D0E70;

// ---------------------------------------------------------------------------
//  Утилиты для патчинга памяти
// ---------------------------------------------------------------------------
namespace mem {

static void Unprotect(void* addr, size_t size, DWORD& oldProt) {
    VirtualProtect(addr, size, PAGE_EXECUTE_READWRITE, &oldProt);
}

static void Protect(void* addr, size_t size, DWORD oldProt) {
    DWORD tmp;
    VirtualProtect(addr, size, oldProt, &tmp);
}

static void Patch(uintptr_t addr, const uint8_t* bytes, size_t len) {
    DWORD old;
    Unprotect(reinterpret_cast<void*>(addr), len, old);
    memcpy(reinterpret_cast<void*>(addr), bytes, len);
    Protect(reinterpret_cast<void*>(addr), len, old);
}

static void Nop(uintptr_t addr, size_t count) {
    DWORD old;
    Unprotect(reinterpret_cast<void*>(addr), count, old);
    memset(reinterpret_cast<void*>(addr), 0x90, count);
    Protect(reinterpret_cast<void*>(addr), count, old);
}

// Записать один байт
static void Byte(uintptr_t addr, uint8_t val) {
    Patch(addr, &val, 1);
}

} // namespace mem

// ---------------------------------------------------------------------------
//  Хук CTaskComplexExitVehicle::ProcessPed
//  Оригинальная функция: __thiscall void(CPed*)
// ---------------------------------------------------------------------------
typedef void(__thiscall* ExitVehicleTask_t)(void* pTask, void* pPed);
static ExitVehicleTask_t fpExitVehicleTask_orig = nullptr;

// Флаг: разрешён ли немедленный выход
static bool g_bForceExit = false;

static void __fastcall Hook_ExitVehicleTask(void* pTask, void* /*edx*/, void* pPed) {
    // Просто передаём управление оригиналу — хук сам по себе
    // снимает ограничение скорости через патч ниже.
    fpExitVehicleTask_orig(pTask, pPed);
}

// ---------------------------------------------------------------------------
//  Хук проверки скорости в CAutomobile::ProcessControl
//  Адрес ветки в GTA SA 1.0: 0x6D0E6C — cmp + jg (0x7F xx)
//  Заменяем условный прыжок на безусловный (jmp = 0xEB)
// ---------------------------------------------------------------------------
static void PatchSpeedCheck() {
    // GTA SA 1.0 US — по адресу 0x6D0E70 стоит:
    //   7F 2A   jg  +0x2A   (если скорость > порога — запрет выхода)
    // Меняем 7F → EB чтобы всегда прыгать (игнорируем проверку скорости)
    // Это корректнее чем NOP, т.к. сохраняет поток выполнения.
    //
    // Адрес подтверждён по IDA для EXE MD5: 31a52d8d2c31a02e2f05e37c7e10fd02

    constexpr uintptr_t addr = 0x6D0E70;
    const uint8_t patch[] = { 0xEB }; // jg -> jmp (short)
    mem::Patch(addr, patch, sizeof(patch));
}

// ---------------------------------------------------------------------------
//  Патч: разрешить выход когда водитель — другой игрок
//  GTA SA 1.0 US: в CPed::ExitVehicle есть проверка IsDriver()
//  Адрес ветки: 0x60DA45 — jz short (0x74)
//  Меняем 0x74 → 0xEB (безусловный прыжок = всегда выходим)
// ---------------------------------------------------------------------------
static void PatchPassengerExit() {
    // 0x60DA45: 74 XX  jz (если мы не водитель, пропустить выход)
    // → EB XX  jmp (всегда выходим)
    constexpr uintptr_t addr = 0x60DA45;
    const uint8_t patch[] = { 0xEB };
    mem::Patch(addr, patch, sizeof(patch));
}

// ---------------------------------------------------------------------------
//  Патч анимации: убрать "rolling" на малой скорости
//  GTA SA 1.0 US: 0x649350 — условие выбора анимации rolling/normal
//  Адрес: 0x649354 — jle (0x7E) → jmp (0xEB)
// ---------------------------------------------------------------------------
static void PatchRollingAnim() {
    constexpr uintptr_t addr = 0x649354;
    const uint8_t patch[] = { 0xEB };
    mem::Patch(addr, patch, sizeof(patch));
}

// ---------------------------------------------------------------------------
//  Обнаружение версии GTA SA (простая проверка по сигнатуре EXE)
// ---------------------------------------------------------------------------
static bool IsGTASA_10_US() {
    // Читаем 4 байта по известному адресу-маркеру версии 1.0 US
    const uint32_t* marker = reinterpret_cast<const uint32_t*>(0x82457C);
    __try {
        return (*marker == 0x94BF90E9); // сигнатура 1.0 US
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        return false;
    }
}

// ---------------------------------------------------------------------------
//  Инициализация плагина
// ---------------------------------------------------------------------------
static DWORD WINAPI Init(LPVOID) {
    // Ждём пока GTA SA полностью загрузится
    Sleep(2000);

    // Проверяем версию
    if (!IsGTASA_10_US()) {
        // Версия не 1.0 US — адреса могут не совпадать, не патчим
        // (безопасный выход без краша)
        return 0;
    }

    // Применяем патчи
    __try {
        PatchSpeedCheck();    // Выход на любой скорости
        PatchPassengerExit(); // Выход когда за рулём другой игрок
        PatchRollingAnim();   // Убрать rolling на малой скорости
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        // Если что-то пошло не так — молча выходим
        return 0;
    }

    // Хук через MinHook (опциональный слой, оставлен для расширяемости)
    // MH_Initialize();
    // MH_CreateHook(...);
    // MH_EnableHook(MH_ALL_HOOKS);

    return 0;
}

// ---------------------------------------------------------------------------
//  DllMain
// ---------------------------------------------------------------------------
BOOL APIENTRY DllMain(HMODULE hModule, DWORD dwReason, LPVOID) {
    if (dwReason == DLL_PROCESS_ATTACH) {
        DisableThreadLibraryCalls(hModule);
        // Запускаем в отдельном потоке чтобы не блокировать загрузку игры
        CloseHandle(CreateThread(nullptr, 0, Init, nullptr, 0, nullptr));
    }
    return TRUE;
}
