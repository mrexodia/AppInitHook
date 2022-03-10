# Check if we're compiling with MSVC
if(NOT MSVC)
	message(FATAL_ERROR "Non-MSVC compilers are not supported!")
endif()

# Fail when trying to compile to a path that contains spaces
string(FIND "${PROJECT_BINARY_DIR}" " " SPACE_INDEX)
if(NOT SPACE_INDEX STREQUAL "-1")
	message(FATAL_ERROR "Compiling in a path that contains spaces is not supported!")
endif()

# Build the register_AppInitDLL to register AppInitDispatcher.dll
add_custom_target(register_AppInitDLLs
	COMMAND
		"${CMAKE_COMMAND}" --build "${PROJECT_BINARY_DIR}" --target AppInitDispatcher --config $<CONFIG>
    COMMAND
        "${CMAKE_COMMAND}" "-DAPPINITDISPATCHER_PATH=$<TARGET_FILE:AppInitDispatcher>" -DCMAKE_SIZEOF_VOID_P=${CMAKE_SIZEOF_VOID_P} -P "${CMAKE_CURRENT_SOURCE_DIR}/CMake/register_AppInitDLLs.cmake"
    SOURCES
        CMake/register_x64.reg.in
        CMake/register_x86.reg.in
)

# Create a skeleton private module
if(NOT EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/Private")
	file(
		COPY "${CMAKE_CURRENT_SOURCE_DIR}/CMake/cmake.toml"
		DESTINATION "${CMAKE_CURRENT_SOURCE_DIR}/Private"
	)
	file(
		COPY "${CMAKE_CURRENT_SOURCE_DIR}/Modules/AppInitExampleModule/AppInitExampleModule.cpp"
		DESTINATION "${CMAKE_CURRENT_SOURCE_DIR}/Private/MyPrivateModule"
	)
	file(RENAME
		"${CMAKE_CURRENT_SOURCE_DIR}/Private/MyPrivateModule/AppInitExampleModule.cpp"
		"${CMAKE_CURRENT_SOURCE_DIR}/Private/MyPrivateModule/MyPrivateModule.cpp"
	)
endif()