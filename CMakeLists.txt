cmake_minimum_required(VERSION 3.16)
project(ExitFix CXX)

# Обязательно x86 (32-бит) — GTA SA 32-битная
# Установи: cmake -A Win32 ..

set(CMAKE_CXX_STANDARD 17)

add_library(ExitFix SHARED
    dllmain.cpp
)

# Переименовываем .dll → .asi
set_target_properties(ExitFix PROPERTIES
    SUFFIX ".asi"
    PREFIX ""
)

# Линковка с MinHook (статическая)
# Скачай MinHook с https://github.com/TsudaKageyu/minhook/releases
# и положи libMinHook.x86.lib + MinHook.h в папку проекта
target_link_libraries(ExitFix
    "${CMAKE_SOURCE_DIR}/libMinHook.x86.lib"
)

target_compile_definitions(ExitFix PRIVATE
    WIN32_LEAN_AND_MEAN
    NOMINMAX
)

# Оптимизация размера и скорости
target_compile_options(ExitFix PRIVATE
    /O2 /Oi /GL /GS-
)
target_link_options(ExitFix PRIVATE
    /LTCG /OPT:REF /OPT:ICF
)
