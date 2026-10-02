set(CMAKE_BUILD_TYPE Debug)


add_library(debloat_rt MODULE
    debloat_rt.cpp
)

target_link_libraries(debloat_rt PRIVATE -static-libgcc -static-libstdc++)

set(CMAKE_CXX_FLAGS "-Wl,--version-script=${CMAKE_CURRENT_SOURCE_DIR}/libdebloatrt.version")
