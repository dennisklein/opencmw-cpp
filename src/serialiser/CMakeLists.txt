cmrc_add_resource_library(
        MUSTACHE_TEST_SERVER_ASSETS ALIAS assets::mustache NAMESPACE assets
        ${CMAKE_CURRENT_SOURCE_DIR}/assets/mustache/default.mustache
        ${CMAKE_CURRENT_SOURCE_DIR}/assets/mustache/Services.mustache
)

unset(headers)
list(APPEND headers
        include/IoBuffer.hpp
        include/IoSerialiser.hpp
        include/IoSerialiserCmwLight.hpp
        include/IoSerialiserJson.hpp
        include/IoSerialiserYAML.hpp
        include/IoSerialiserYaS.hpp
        include/MultiArray.hpp
        include/MustacheSerialiser.hpp
        include/QuerySerialiser.hpp
        include/fast_float.h
)

add_library(serialiser INTERFACE)
target_include_directories(serialiser INTERFACE $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include> $<INSTALL_INTERFACE:${CMAKE_INSTALL_PREFIX}/include/>)
target_link_libraries(serialiser INTERFACE $<BUILD_INTERFACE: mp-units::mp-units mustache::mustache assets::mustache> refl-cpp::refl-cpp core utils)
set_target_properties(serialiser PROPERTIES PUBLIC_HEADER "${headers}")

install(
        TARGETS serialiser
        EXPORT opencmwTargets
        PUBLIC_HEADER DESTINATION include/opencmw
)

# setup tests
if(ENABLE_TESTING)
  add_subdirectory(test)
endif()
