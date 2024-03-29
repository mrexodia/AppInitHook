# This file is automatically generated from cmake.toml - DO NOT EDIT
# See https://github.com/build-cpp/cmkr for more information

# Create a configure-time dependency on cmake.toml to improve IDE support
if(CMKR_ROOT_PROJECT)
	configure_file(cmake.toml cmake.toml COPYONLY)
endif()

# Target AppInitExampleModule
set(CMKR_TARGET AppInitExampleModule)
set(AppInitExampleModule_SOURCES "")

list(APPEND AppInitExampleModule_SOURCES
	"AppInitExampleModule/AppInitExampleModule.cpp"
)

list(APPEND AppInitExampleModule_SOURCES
	cmake.toml
)

set(CMKR_SOURCES ${AppInitExampleModule_SOURCES})
add_library(AppInitExampleModule SHARED)

if(AppInitExampleModule_SOURCES)
	target_sources(AppInitExampleModule PRIVATE ${AppInitExampleModule_SOURCES})
endif()

source_group(TREE ${CMAKE_CURRENT_SOURCE_DIR} FILES ${AppInitExampleModule_SOURCES})

target_link_libraries(AppInitExampleModule PUBLIC
	HookDll
)

unset(CMKR_TARGET)
unset(CMKR_SOURCES)

# Target clang-cl-hacks
set(CMKR_TARGET clang-cl-hacks)
set(clang-cl-hacks_SOURCES "")

list(APPEND clang-cl-hacks_SOURCES
	"clang-cl-hacks/clang-cl-hacks.cpp"
)

list(APPEND clang-cl-hacks_SOURCES
	cmake.toml
)

set(CMKR_SOURCES ${clang-cl-hacks_SOURCES})
add_library(clang-cl-hacks SHARED)

if(clang-cl-hacks_SOURCES)
	target_sources(clang-cl-hacks PRIVATE ${clang-cl-hacks_SOURCES})
endif()

source_group(TREE ${CMAKE_CURRENT_SOURCE_DIR} FILES ${clang-cl-hacks_SOURCES})

target_link_libraries(clang-cl-hacks PUBLIC
	HookDll
)

unset(CMKR_TARGET)
unset(CMKR_SOURCES)

# Target CMakeClean
set(CMKR_TARGET CMakeClean)
set(CMakeClean_SOURCES "")

list(APPEND CMakeClean_SOURCES
	"CMakeClean/CMakeClean.cpp"
)

list(APPEND CMakeClean_SOURCES
	cmake.toml
)

set(CMKR_SOURCES ${CMakeClean_SOURCES})
add_library(CMakeClean SHARED)

if(CMakeClean_SOURCES)
	target_sources(CMakeClean PRIVATE ${CMakeClean_SOURCES})
endif()

source_group(TREE ${CMAKE_CURRENT_SOURCE_DIR} FILES ${CMakeClean_SOURCES})

target_link_libraries(CMakeClean PUBLIC
	HookDll
)

unset(CMKR_TARGET)
unset(CMKR_SOURCES)

# Target CmdImproved
set(CMKR_TARGET CmdImproved)
set(CmdImproved_SOURCES "")

list(APPEND CmdImproved_SOURCES
	"CmdImproved/CmdImproved.cpp"
)

list(APPEND CmdImproved_SOURCES
	cmake.toml
)

set(CMKR_SOURCES ${CmdImproved_SOURCES})
add_library(CmdImproved SHARED)

if(CmdImproved_SOURCES)
	target_sources(CmdImproved PRIVATE ${CmdImproved_SOURCES})
endif()

source_group(TREE ${CMAKE_CURRENT_SOURCE_DIR} FILES ${CmdImproved_SOURCES})

target_link_libraries(CmdImproved PUBLIC
	HookDll
)

unset(CMKR_TARGET)
unset(CMKR_SOURCES)

# Target ConhostLoader
set(CMKR_TARGET ConhostLoader)
set(ConhostLoader_SOURCES "")

list(APPEND ConhostLoader_SOURCES
	"ConhostLoader/ConhostLoader.cpp"
)

list(APPEND ConhostLoader_SOURCES
	cmake.toml
)

set(CMKR_SOURCES ${ConhostLoader_SOURCES})
add_library(ConhostLoader SHARED)

if(ConhostLoader_SOURCES)
	target_sources(ConhostLoader PRIVATE ${ConhostLoader_SOURCES})
endif()

source_group(TREE ${CMAKE_CURRENT_SOURCE_DIR} FILES ${ConhostLoader_SOURCES})

target_link_libraries(ConhostLoader PUBLIC
	HookDll
)

unset(CMKR_TARGET)
unset(CMKR_SOURCES)

# Target ExitProcess
set(CMKR_TARGET ExitProcess)
set(ExitProcess_SOURCES "")

list(APPEND ExitProcess_SOURCES
	"ExitProcess/ExitProcess.cpp"
)

list(APPEND ExitProcess_SOURCES
	cmake.toml
)

set(CMKR_SOURCES ${ExitProcess_SOURCES})
add_library(ExitProcess SHARED)

if(ExitProcess_SOURCES)
	target_sources(ExitProcess PRIVATE ${ExitProcess_SOURCES})
endif()

source_group(TREE ${CMAKE_CURRENT_SOURCE_DIR} FILES ${ExitProcess_SOURCES})

target_link_libraries(ExitProcess PUBLIC
	HookDll
)

unset(CMKR_TARGET)
unset(CMKR_SOURCES)

# Target ForceQuit
set(CMKR_TARGET ForceQuit)
set(ForceQuit_SOURCES "")

list(APPEND ForceQuit_SOURCES
	"ForceQuit/ForceQuit.cpp"
)

list(APPEND ForceQuit_SOURCES
	cmake.toml
)

set(CMKR_SOURCES ${ForceQuit_SOURCES})
add_library(ForceQuit SHARED)

if(ForceQuit_SOURCES)
	target_sources(ForceQuit PRIVATE ${ForceQuit_SOURCES})
endif()

source_group(TREE ${CMAKE_CURRENT_SOURCE_DIR} FILES ${ForceQuit_SOURCES})

target_link_libraries(ForceQuit PUBLIC
	HookDll
)

unset(CMKR_TARGET)
unset(CMKR_SOURCES)

# Target GitMagic
set(CMKR_TARGET GitMagic)
set(GitMagic_SOURCES "")

list(APPEND GitMagic_SOURCES
	"GitMagic/GitMagic.cpp"
)

list(APPEND GitMagic_SOURCES
	cmake.toml
)

set(CMKR_SOURCES ${GitMagic_SOURCES})
add_library(GitMagic SHARED)

if(GitMagic_SOURCES)
	target_sources(GitMagic PRIVATE ${GitMagic_SOURCES})
endif()

source_group(TREE ${CMAKE_CURRENT_SOURCE_DIR} FILES ${GitMagic_SOURCES})

target_link_libraries(GitMagic PUBLIC
	HookDll
)

unset(CMKR_TARGET)
unset(CMKR_SOURCES)

# Target HighPriority
set(CMKR_TARGET HighPriority)
set(HighPriority_SOURCES "")

list(APPEND HighPriority_SOURCES
	"HighPriority/HighPriority.cpp"
)

list(APPEND HighPriority_SOURCES
	cmake.toml
)

set(CMKR_SOURCES ${HighPriority_SOURCES})
add_library(HighPriority SHARED)

if(HighPriority_SOURCES)
	target_sources(HighPriority PRIVATE ${HighPriority_SOURCES})
endif()

source_group(TREE ${CMAKE_CURRENT_SOURCE_DIR} FILES ${HighPriority_SOURCES})

target_link_libraries(HighPriority PUBLIC
	HookDll
)

unset(CMKR_TARGET)
unset(CMKR_SOURCES)

# Target NoSoftwareInventory
set(CMKR_TARGET NoSoftwareInventory)
set(NoSoftwareInventory_SOURCES "")

list(APPEND NoSoftwareInventory_SOURCES
	"NoSoftwareInventory/NoSoftwareInventory.cpp"
)

list(APPEND NoSoftwareInventory_SOURCES
	cmake.toml
)

set(CMKR_SOURCES ${NoSoftwareInventory_SOURCES})
add_library(NoSoftwareInventory SHARED)

if(NoSoftwareInventory_SOURCES)
	target_sources(NoSoftwareInventory PRIVATE ${NoSoftwareInventory_SOURCES})
endif()

source_group(TREE ${CMAKE_CURRENT_SOURCE_DIR} FILES ${NoSoftwareInventory_SOURCES})

target_link_libraries(NoSoftwareInventory PUBLIC
	HookDll
)

unset(CMKR_TARGET)
unset(CMKR_SOURCES)

# Target TotalCommander
set(CMKR_TARGET TotalCommander)
set(TotalCommander_SOURCES "")

list(APPEND TotalCommander_SOURCES
	"TotalCommander/TotalCommander.cpp"
)

list(APPEND TotalCommander_SOURCES
	cmake.toml
)

set(CMKR_SOURCES ${TotalCommander_SOURCES})
add_library(TotalCommander SHARED)

if(TotalCommander_SOURCES)
	target_sources(TotalCommander PRIVATE ${TotalCommander_SOURCES})
endif()

source_group(TREE ${CMAKE_CURRENT_SOURCE_DIR} FILES ${TotalCommander_SOURCES})

target_link_libraries(TotalCommander PUBLIC
	HookDll
)

unset(CMKR_TARGET)
unset(CMKR_SOURCES)

# Target WerfaultMagic
set(CMKR_TARGET WerfaultMagic)
set(WerfaultMagic_SOURCES "")

list(APPEND WerfaultMagic_SOURCES
	"WerfaultMagic/WerfaultMagic.cpp"
)

list(APPEND WerfaultMagic_SOURCES
	cmake.toml
)

set(CMKR_SOURCES ${WerfaultMagic_SOURCES})
add_library(WerfaultMagic SHARED)

if(WerfaultMagic_SOURCES)
	target_sources(WerfaultMagic PRIVATE ${WerfaultMagic_SOURCES})
endif()

source_group(TREE ${CMAKE_CURRENT_SOURCE_DIR} FILES ${WerfaultMagic_SOURCES})

target_link_libraries(WerfaultMagic PUBLIC
	HookDll
)

unset(CMKR_TARGET)
unset(CMKR_SOURCES)

# Target WowUndirect
set(CMKR_TARGET WowUndirect)
set(WowUndirect_SOURCES "")

list(APPEND WowUndirect_SOURCES
	"WowUndirect/WowUndirect.cpp"
)

list(APPEND WowUndirect_SOURCES
	cmake.toml
)

set(CMKR_SOURCES ${WowUndirect_SOURCES})
add_library(WowUndirect SHARED)

if(WowUndirect_SOURCES)
	target_sources(WowUndirect PRIVATE ${WowUndirect_SOURCES})
endif()

source_group(TREE ${CMAKE_CURRENT_SOURCE_DIR} FILES ${WowUndirect_SOURCES})

target_link_libraries(WowUndirect PUBLIC
	HookDll
)

unset(CMKR_TARGET)
unset(CMKR_SOURCES)

